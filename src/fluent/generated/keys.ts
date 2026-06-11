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
                    'nowisor-attachment-role-restriction': {
                        table: 'scan_script_only_check'
                        id: '625d958169f541588e3c45128468e1ad'
                    }
                    'nowisor-audit-coverage-gap': {
                        table: 'scan_script_only_check'
                        id: '22fcea3957b9db3ce7493c4fac419286'
                    }
                    'nowisor-basic-auth-enforcement-posture': {
                        table: 'scan_script_only_check'
                        id: 'a51427c6fb91460fb88a6f2aa3793d44'
                    }
                    'nowisor-basic-auth-hybrid-undecided': {
                        table: 'scan_script_only_check'
                        id: '844180c573e842f7928a36ab8a9e6673'
                    }
                    'nowisor-basic-auth-restriction-inactive': {
                        table: 'scan_script_only_check'
                        id: '1c251545fa984bd8ab8cbf23d38352a5'
                    }
                    'nowisor-basic-auth-role-without-wsao': {
                        table: 'scan_script_only_check'
                        id: 'bd006a1828584c9baea63fc38c2dd58c'
                    }
                    'nowisor-basic-auth-stale-api-accounts': {
                        table: 'scan_script_only_check'
                        id: 'b7e1eb01b6074286b82a423fdd3bb362'
                    }
                    'nowisor-cookie-http-only': {
                        table: 'scan_script_only_check'
                        id: '8b4167394dde4c07ba44ea980d18f62e'
                    }
                    'nowisor-cookie-secure': {
                        table: 'scan_script_only_check'
                        id: '9f98937cd5de48a7ace0db41563815f1'
                    }
                    'nowisor-cross-scope-privilege-grants': {
                        table: 'scan_script_only_check'
                        id: '7187719a3f9247c6840749c85e019c15'
                    }
                    'nowisor-csrf-token-enforcement': {
                        table: 'scan_script_only_check'
                        id: 'b20ecfa9500e4ac48fcab135b839b352'
                    }
                    'nowisor-direct-property-write': {
                        table: 'scan_linter_check'
                        id: '944dd3446fa34308b609a791c342812e'
                    }
                    'nowisor-domain-separation-script-include': {
                        table: 'scan_linter_check'
                        id: '590cc7b0c6e6480396bd41ca1b8621d2'
                    }
                    'nowisor-elevated-role-assignments': {
                        table: 'scan_script_only_check'
                        id: 'a1c3e51006cd447da4f4de179085cef2'
                    }
                    'nowisor-eval-usage-detector': {
                        table: 'scan_linter_check'
                        id: 'b6d3e0840f21424e908a542597b07387'
                    }
                    'nowisor-external-auth-policy': {
                        table: 'scan_script_only_check'
                        id: 'a0f9dc4c6a5b4fefbd16aa2a88427627'
                    }
                    'nowisor-fabricated-property-references': {
                        table: 'scan_script_only_check'
                        id: '7da698ab73c8463398d024182ad410d2'
                    }
                    'nowisor-glide-evaluator-detector': {
                        table: 'scan_linter_check'
                        id: '4084bf6acf6f4c1e8cea9f2cf7c2390d'
                    }
                    'nowisor-glide-record-vs-secure': {
                        table: 'scan_linter_check'
                        id: '96706c3dfd4b4f3998182f89ac36bc96'
                    }
                    'nowisor-hardcoded-credentials': {
                        table: 'scan_linter_check'
                        id: '0122be86cbdf4fda8fcce5ba95251a54'
                    }
                    'nowisor-inactive-users-with-roles': {
                        table: 'scan_script_only_check'
                        id: 'd4c86b7e103144cc86334cc4d0a01055'
                    }
                    'nowisor-meta-active-check-coverage': {
                        table: 'scan_script_only_check'
                        id: '9bd7974e937e4f3496c3ed7e3a7278ff'
                    }
                    'nowisor-mfa-enforcement': {
                        table: 'scan_script_only_check'
                        id: '00ffbc4fde644c409592598c0ff0b4a7'
                    }
                    'nowisor-oob-acl-modifications': {
                        table: 'scan_script_only_check'
                        id: 'c2b1a31d33dc470bb380389e4c2c6147'
                    }
                    'nowisor-platform-build-drift': {
                        table: 'scan_script_only_check'
                        id: '3316387bbeaa4e9880dd291bc8e66f11'
                    }
                    'nowisor-priv-sys-app-read': {
                        table: 'sys_scope_privilege'
                        id: 'd9f6f23bef1b4385a68705e746e4018a'
                    }
                    'nowisor-priv-sys-db-object-read': {
                        table: 'sys_scope_privilege'
                        id: '3d8311310cff40fca278002e82ba535c'
                    }
                    'nowisor-priv-sys-dictionary-read': {
                        table: 'sys_scope_privilege'
                        id: '1b16edafae8f49659293ea013fde783f'
                    }
                    'nowisor-priv-sys-scope-privilege-read': {
                        table: 'sys_scope_privilege'
                        id: '0a59447643fe42508d82c7c3920d5e72'
                    }
                    'nowisor-priv-sys-scope-read': {
                        table: 'sys_scope_privilege'
                        id: 'bf4fa06793584a0db3aa81ff92da8361'
                    }
                    'nowisor-priv-sys-script-include-read': {
                        table: 'sys_scope_privilege'
                        id: 'c2e1e9de56104e008a4fa4a59337a71d'
                    }
                    'nowisor-priv-sys-script-read': {
                        table: 'sys_scope_privilege'
                        id: '3e70494b982048669fbbbd88065306b7'
                    }
                    'nowisor-priv-sys-security-acl-read': {
                        table: 'sys_scope_privilege'
                        id: '505fc16790814ca49235c0d3143d315f'
                    }
                    'nowisor-priv-sys-security-acl-role-read': {
                        table: 'sys_scope_privilege'
                        id: '07ecbcf96a224d03b5f501ea947da3d7'
                    }
                    'nowisor-priv-sys-ui-action-read': {
                        table: 'sys_scope_privilege'
                        id: '3c7ee64c992f43cd8ee9432ceac38720'
                    }
                    'nowisor-priv-sys-update-xml-read': {
                        table: 'sys_scope_privilege'
                        id: 'b165a7f0c6124c708be5459f5316360d'
                    }
                    'nowisor-priv-sys-user-basic-auth-exception-read': {
                        table: 'sys_scope_privilege'
                        id: '5d17a61440a1474b96216cf002b6d530'
                    }
                    'nowisor-priv-sys-user-grmember-read': {
                        table: 'sys_scope_privilege'
                        id: 'db77286a068d4782b4e07644e2c3af26'
                    }
                    'nowisor-priv-sys-user-group-read': {
                        table: 'sys_scope_privilege'
                        id: '5a326978629641328122a815d3d769a0'
                    }
                    'nowisor-priv-sys-user-has-role-read': {
                        table: 'sys_scope_privilege'
                        id: '22d228b15ca842e08a4fee89519a414f'
                    }
                    'nowisor-priv-sys-user-read': {
                        table: 'sys_scope_privilege'
                        id: '6a3ad5374b824bf5a6531be1b1f068ec'
                    }
                    'nowisor-priv-sys-user-role-contains-read': {
                        table: 'sys_scope_privilege'
                        id: '409ca1512c6d48d58bf578d96e73d4e7'
                    }
                    'nowisor-priv-sys-user-role-read': {
                        table: 'sys_scope_privilege'
                        id: 'db986acd45394dc08c0eb013ae52916c'
                    }
                    'nowisor-rest-anonymous-access': {
                        table: 'scan_script_only_check'
                        id: '3dad347d6efd4b45ad907f23aad9afce'
                    }
                    'nowisor-secure-cookies': {
                        table: 'scan_script_only_check'
                        id: '9d2c3525bd6b4180a384e411d62439db'
                    }
                    'nowisor-session-timeout': {
                        table: 'scan_script_only_check'
                        id: 'e5655f5ca0da49d29d1e3155c268686d'
                    }
                    'nowisor-set-roles-detector': {
                        table: 'scan_linter_check'
                        id: 'a0389ca5d67241d3a7ffb81547b02573'
                    }
                    'nowisor-set-workflow-false-detector': {
                        table: 'scan_linter_check'
                        id: 'b32509ff97fb4421af60896de0f7d7a5'
                    }
                    'nowisor-update-set-xml-suspicious': {
                        table: 'scan_column_type_check'
                        id: '7d4a295077f24cd69e026ed04181219d'
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
