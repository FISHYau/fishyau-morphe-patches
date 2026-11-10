# Retired compatibility entry point. Never builds, loads patches, or writes output.
[CmdletBinding()]
param(
    [string]$Bundle,
    [string]$InputApk,
    [string]$Out,
    [string]$JavaHome,
    [string]$GradleHome,
    [switch]$Help
)
$ErrorActionPreference = 'Stop'
$guidance = @'
check-termius.ps1 is retired and cannot execute checks.
Use tools/termius-check/run_jvm_checks.py with explicit --scope termius or --scope collection, installed --jdk and --cache-root, and a NEW external --out.
For exact-MPP checks, use the isolated checker_runtime_classpath from that runner's reviewed jvm-checks.json. RuntimeCheckKt requires exactly five arguments:
ABS_EXACT_MPP ABS_TERMIUS_BASE_APK NEW_EXTERNAL_DIRECTORY ABS_MATCHING_CATALOG ABS_REPO
See tools/termius-check/README.md for the exact invocation and scope/approval limits. JVM test JARs are not Android MPPs.
'@
if ($Help) {
    $guidance
    return
}
throw $guidance
