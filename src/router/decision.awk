# Pure router decision. Reads one previous TSV state; never changes the network.
# All times are integer /proc/uptime seconds, never wall clock.
function uint(x) { return x ~ /^[0-9]+$/ && length(x) <= 10 && x+0 <= 2147483647 }
function stamp(x) { return x == -1 || uint(x) }
function emit() {
    print epoch, mode, failures, good_since, last_sample, now, requested, reason
}
function reset() { mode="provider"; failures=0; good_since=-1; last_sample=-1 }
BEGIN {
    FS=OFS="\t"; reset(); rows=0; valid=0
    if (epoch !~ /^[0-9a-f]+$/ || length(epoch)!=64 || !uint(now) ||
        !uint(failures_limit) || failures_limit<1 || failures_limit>20 ||
        !uint(recovery_seconds) || recovery_seconds<1 || recovery_seconds>3600 ||
        !uint(max_age) || max_age<1 || max_age>60 ||
        (requested!="auto" && requested!="provider") ||
        (integrity!="0" && integrity!="1")) {
        bad_arguments=1; exit 64
    }
}
{
    rows++
    if (rows==1 && NF==8 && $1==epoch && ($2=="provider" || $2=="home") &&
        uint($3) && $3<=failures_limit && stamp($4) && stamp($5) && uint($6) &&
        $4<=$5 && $5<=$6 && $6<=now && $7==requested) {
        mode=$2; failures=$3+0; good_since=$4+0; last_sample=$5+0; valid=1
    }
}
END {
    if (bad_arguments) exit 64
    if (!valid || rows!=1) reset()
    if (requested=="provider") { reset(); reason="manual-provider"; emit(); exit }
    if (integrity!="1") { reset(); reason="integrity-lost"; emit(); exit }
    if ((sample_state!="up" && sample_state!="down") || !uint(sample_at) ||
        sample_at>now || now-sample_at>max_age) {
        reset(); reason="unavailable-health"; emit(); exit
    }
    # A missing interval cannot be credited as uninterrupted recovery. Even an
    # up sample after a long gap starts from the native direct base again.
    if (last_sample>=0 && (sample_at<last_sample || sample_at-last_sample>max_age)) reset()
    if (sample_at==last_sample) { reason="awaiting-new-sample"; emit(); exit }
    last_sample=sample_at+0
    if (sample_state=="down") {
        good_since=-1
        if (failures<failures_limit) failures++
        if (failures>=failures_limit) { mode="provider"; reason="server-failed" }
        else reason="failure-grace"
    } else {
        failures=0
        if (good_since<0) good_since=sample_at+0
        if (mode=="home") reason="server-held"
        else if (sample_at-good_since>=recovery_seconds) { mode="home"; reason="server-recovered" }
        else reason="waiting-recovery"
    }
    emit()
}
