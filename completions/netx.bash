_netx_complete() {
    local current="${COMP_WORDS[COMP_CWORD]}"
    local commands='dns http tls diagnose check tcp ports ping trace'
    if (( COMP_CWORD == 1 )); then
        COMPREPLY=( $(compgen -W "$commands --help --version" -- "$current") )
        return
    fi
    case "${COMP_WORDS[COMP_CWORD-1]}" in
        --type) COMPREPLY=( $(compgen -W 'A AAAA CNAME MX NS TXT SOA CAA PTR' -- "$current") ); return ;;
        --ca-file) COMPREPLY=( $(compgen -f -- "$current") ); return ;;
    esac
    local options='--help --json --timeout'
    case "${COMP_WORDS[1]}" in
        dns) options+=' --type --server --compare' ;;
        http) options+=' --max-redirects --max-body --ca-file -4 -6' ;;
        tls) options+=' --chain --ca-file -4 -6' ;;
        diagnose|check) options+=' --deployment --chain --ca-file --max-redirects --max-body -4 -6' ;;
        tcp) options+=' --ports -4 -6' ;;
        ports) options='--help --json --established --port -4 -6' ;;
        ping) options+=' --count --port -4 -6' ;;
        trace) options+=' --max-hops -4 -6' ;;
    esac
    COMPREPLY=( $(compgen -W "$options" -- "$current") )
}
complete -F _netx_complete netx
