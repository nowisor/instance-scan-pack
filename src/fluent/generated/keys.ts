import '@servicenow/sdk/global'

declare global {
    namespace Now {
        namespace Internal {
            interface Keys extends KeysRegistry {
                explicit: {
                    bom_json: {
                        table: 'sys_module'
                        id: '9b21efd9b9c6432ca8554537aebc76bf'
                    }
                    'nowisor-admin-role-concentration': {
                        table: 'scan_script_only_check'
                        id: 'e27b5266082240d8bf97d231ca14ca52'
                    }
                    'nowisor-csrf-token-enforcement': {
                        table: 'scan_script_only_check'
                        id: 'b20ecfa9500e4ac48fcab135b839b352'
                    }
                    'nowisor-eval-usage-detector': {
                        table: 'scan_linter_check'
                        id: 'b6d3e0840f21424e908a542597b07387'
                    }
                    package_json: {
                        table: 'sys_module'
                        id: 'f60ef7d422a84adeb80533b2a6e00e58'
                    }
                    src_server_script_ts: {
                        table: 'sys_module'
                        id: '66ff96f843de48529f90e0963307b260'
                    }
                }
            }
        }
    }
}
