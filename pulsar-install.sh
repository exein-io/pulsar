#!/bin/sh

# Adapted from https://github.com/rust-lang/rustup/blob/master/rustup-init.sh

# This is just a little script that can be downloaded from the internet to
# install pulsar. It just does platform detection, downloads the right files
# and install them.

# It runs on Unix shells like {a,ba,da,k,z}sh. It uses the common `local`
# extension. Note: Most shells limit `local` to 1 var per line, contra bash.

INSTALLER_VERSION=0.1

usage() {
    cat 1>&2 <<EOF
pulsar-install $INSTALLER_VERSION
The installer for pulsar
USAGE:
    pulsar-install [OPTIONS]
OPTIONS:
    -h, --help              Prints help information
    -V, --version           Prints version information
EOF
}

version() {
    cat 1>&2 <<EOF
pulsar-install $INSTALLER_VERSION
EOF
}

main() {

    # Check commands
    need_cmd mktemp
    need_cmd curl
    need_cmd uname
    need_cmd ldd
    need_cmd cat
    need_cmd touch
    need_cmd install

    # Parse command line
    for arg in "$@"; do
        case "$arg" in
            --help)
                usage
                exit 0
                ;;
            --version)
                version
                exit 0
                ;;
            *)
                OPTIND=1
                if [ "${arg%%--*}" = "" ]; then
                    err "unrecognized argument. launch with --help to print usage"
                    exit 1
                fi
                while getopts :hy sub_arg "$arg"; do
                    case "$sub_arg" in
                        h)
                            usage
                            exit 0
                            ;;
                        V)
                            version
                            exit 0
                            ;;
                        *)
                            err "unrecognized argument. launch with --help to print usage"
                            exit 1
                            ;;
                        esac
                done
                ;;
        esac
    done

    # Get architecture
    get_release_variant || return 1
    local _arch="$RETVAL"
    # assert_nz "$_arch" "arch"

    # Create temporary directory
    local _dir
    if ! _dir="$(ensure mktemp -d)"; then
        # Because the previous command ran in a subshell, we must manually
        # propagate exit status.
        exit 1
    fi
    ensure mkdir -p "$_dir"

    printf '%s\n' 'info: downloading files' 1>&2

    # Download pulsar-exec
    ensure downloader "https://github.com/Exein-io/pulsar/releases/latest/download/pulsar-exec${_arch}" "${_dir}/pulsar-exec"

    # Download scripts
    ensure downloader "https://raw.githubusercontent.com/Exein-io/pulsar/main/scripts/pulsar" "${_dir}/pulsar"
    ensure downloader "https://raw.githubusercontent.com/Exein-io/pulsar/main/scripts/pulsard" "${_dir}/pulsard"

    printf '%s\n' 'info: installing files' 1>&2

    local _bindir="/usr/bin"

    local _install="install"
    if (( $EUID != 0 )); then
        need_cmd sudo
        _install="sudo ${_install}"
    fi

    # ensure $_install -d ${_bindir}

    # Install pulsar-exec
    ensure $_install -m 755 "${_dir}/pulsar-exec" ${_bindir}

    # Insalll scripts
    ensure $_install -m 755 "${_dir}/pulsar" ${_bindir}
    ensure $_install -m 755 "${_dir}/pulsard" ${_bindir}

    printf '%s\n' 'info: generating configuration' 1>&2

    local _pulsar_config_dir="/var/lib/pulsar"
    local _pulsar_rules_dir="${_pulsar_config_dir}/rules"

    ensure $_install -d ${_pulsar_config_dir}
    ensure $_install -d ${_pulsar_rules_dir}

    # Generate and install configuration
    local _temp_config_file="${_dir}/pulsar.ini"
    ensure generate_basic_config "${_temp_config_file}"
    ensure $_install -m 644 ${_temp_config_file} "${_pulsar_config_dir}/pulsar.ini"

    printf '%s\n' 'info: installing example rule' 1>&2

    # Install example rule
    local _temp_rule_file="${_dir}/example_rule.yaml"
    ensure generate_basic_rule "${_temp_rule_file}"
    ensure $_install -m 644 ${_temp_rule_file} "${_pulsar_rules_dir}/example_rule.yaml"

    printf '%s\n' 'info: cleaning' 1>&2
    ignore rm -rf "$_dir"

    printf '%s\n' 'info: installation complete' 1>&2

}

generate_basic_config() {
    touch $1
}

generate_basic_rule() {
    touch $1
}

check_proc() {
    # Check for /proc by looking for the /proc/self/exe link
    # This is only run on Linux
    if ! test -L /proc/self/exe ; then
        err "fatal: Unable to find /proc/self/exe.  Is /proc mounted?  Installation cannot proceed without /proc."
    fi
}

get_bitness() {
    need_cmd head
    # Architecture detection without dependencies beyond coreutils.
    # ELF files start out "\x7fELF", and the following byte is
    #   0x01 for 32-bit and
    #   0x02 for 64-bit.
    # The printf builtin on some shells like dash only supports octal
    # escape sequences, so we use those.
    local _current_exe_head
    _current_exe_head=$(head -c 5 /proc/self/exe )
    if [ "$_current_exe_head" = "$(printf '\177ELF\001')" ]; then
        echo 32
    elif [ "$_current_exe_head" = "$(printf '\177ELF\002')" ]; then
        echo 64
    else
        err "unknown platform bitness"
    fi
}

get_endianness() {
    local cputype=$1
    local suffix_eb=$2
    local suffix_el=$3

    # detect endianness without od/hexdump, like get_bitness() does.
    need_cmd head
    need_cmd tail

    local _current_exe_endianness
    _current_exe_endianness="$(head -c 6 /proc/self/exe | tail -c 1)"
    if [ "$_current_exe_endianness" = "$(printf '\001')" ]; then
        echo "${cputype}${suffix_el}"
    elif [ "$_current_exe_endianness" = "$(printf '\002')" ]; then
        echo "${cputype}${suffix_eb}"
    else
        err "unknown platform endianness"
    fi
}

get_release_variant() {
    local _ostype _cputype _bitness _arch _clibtype
    _ostype="$(uname -s)"
    _cputype="$(uname -m)"
    _clibtype="gnu"

    if [ "$_ostype" = Linux ]; then
        if [ "$(uname -o)" = Android ]; then
            _ostype=Android
        fi
        if ldd --version 2>&1 | grep -q 'musl'; then
            _clibtype="musl"
        fi
    fi

    case "$_ostype" in

        Android)
            _ostype=linux-android
            ;;

        Linux)
            check_proc
            _ostype=unknown-linux-$_clibtype
            _bitness=$(get_bitness)
            ;;

        *)
            err "unsupported OS type: $_ostype"
            ;;

    esac

    case "$_cputype" in

        aarch64 | arm64)
            #_cputype=aarch64
            _arch=-aarch64-static
            ;;

        x86_64 | x86-64 | x64 | amd64)
            #_cputype=x86_64
            if [ "$_clibtype" = gnu ]; then
                _arch=-x86_64
            else
                _arch=-x86_64-static
            fi
            ;;

        riscv64)
            # TODO: _cputype=riscv64gc
            err "installer unsupported CPU type: $_cputype. You have to manually build youself for $_cputype"
            ;;

        *)
            err "unsupported CPU type: $_cputype"

    esac

    # Detect 64-bit linux with 32-bit userland
    if [ "${_ostype}" = unknown-linux-gnu ] && [ "${_bitness}" -eq 32 ]; then
        err "32-bit userland unsupported"
    fi

    RETVAL="$_arch"

}

downloader() {
    local _err

    _err=$(curl $_retry --proto '=https' --tlsv1.2 --silent --show-error --fail --location "$1" --output "$2" 2>&1)
    _status=$?

    if [ -n "$_err" ]; then
        echo "$_err" >&2
    fi
    return $_status

}

say() {
    printf 'pulsar-install: %s\n' "$1"
}

err() {
    say "$1" >&2
    exit 1
}

need_cmd() {
    if ! check_cmd "$1"; then
        err "need '$1' (command not found)"
    fi
}

check_cmd() {
    command -v "$1" > /dev/null 2>&1
}

assert_nz() {
    if [ -z "$1" ]; then err "assert_nz $2"; fi
}

# Run a command that should never fail. If the command fails execution
# will immediately terminate with an error showing the failing
# command.
ensure() {
    if ! "$@"; then err "command failed: $*"; fi
}

# This is just for indicating that commands' results are being
# intentionally ignored. Usually, because it's being executed
# as part of error handling.
ignore() {
    "$@"
}

main "$@" || exit 1