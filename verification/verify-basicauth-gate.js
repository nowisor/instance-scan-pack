// Read-only: safe for production use
// nowisor BASICAUTH check group - PDI verification gate (STRICT-17 leg a).
// Run in System Definition > Scripts - Background. Pure read-only: gs.getProperty
// + GlideRecord. Output captured in fabricated-props-resolution-log.md (2026-06-11,
// dev265147). ASCII-only + short lines (the ES0/Rhino paste parser breaks on
// non-ASCII and on long lines that wrap mid-string).
(function () {
  var S = '___NOT_FOUND___';
  var out = [];
  function L(s) { out.push(s); }
  function T(s) {
    s = '' + s;
    return s.length > 80 ? s.substr(0, 80) + '...' : s;
  }

  L('---NOWISOR_BASICAUTH_VERIFY---');

  L('## instance');
  var ip = ['glide.buildname', 'glide.buildtag', 'glide.war'];
  for (var i = 0; i < ip.length; i++) {
    L('  ' + ip[i] + ' = ' + T(gs.getProperty(ip[i], S)));
  }

  L('## properties.discovered');
  try {
    var pr = new GlideRecord('sys_properties');
    pr.addQuery('name', 'CONTAINS', 'basic_auth');
    pr.orderBy('name');
    pr.setLimit(100);
    pr.query();
    var pn = 0;
    while (pr.next()) {
      pn++;
      L('  ' + pr.getValue('name'));
      L('    = ' + T(pr.getValue('value')));
    }
    if (pn === 0) { L('  (none stored as records)'); }
  } catch (e1) { L('  ERROR ' + e1.message); }

  L('## properties.probe');
  var pp = [
    'glide.authenticate.basic_auth.restriction.active',
    'glide.authenticate.basic_auth.restriction.enforce',
    'glide.authenticate.basic_auth.restriction.enforcement_date',
    'glide.authenticate.basic_auth.restriction.default_decision'
  ];
  for (var j = 0; j < pp.length; j++) {
    var v = gs.getProperty(pp[j], S);
    var tag = (v === S) ? 'NOT_FOUND' : ('REAL[' + T(v) + ']');
    L('  ' + pp[j]);
    L('    => ' + tag);
  }

  L('## roles');
  try {
    var rr = new GlideRecord('sys_user_role');
    rr.addQuery('name', 'CONTAINS', 'basic_auth');
    rr.setLimit(50);
    rr.query();
    var rn = 0;
    while (rr.next()) {
      rn++;
      L('  name=' + rr.getValue('name'));
      L('    sys_id=' + rr.getUniqueValue());
    }
    if (rn === 0) { L('  (none with basic_auth)'); }
    var ex = new GlideRecord('sys_user_role');
    ex.addQuery('name', 'snc_basic_auth_api_access');
    ex.setLimit(1);
    ex.query();
    L('  exact snc_basic_auth_api_access = ' + ex.hasNext());
  } catch (e2) { L('  ERROR ' + e2.message); }

  L('## tables');
  var cands = [];
  try {
    var dbo = new GlideRecord('sys_db_object');
    var q = dbo.addQuery('label', 'CONTAINS', 'basic auth');
    q.addOrCondition('name', 'CONTAINS', 'basic_auth');
    dbo.setLimit(50);
    dbo.query();
    while (dbo.next()) {
      var tn = dbo.getValue('name');
      cands.push(tn);
      L('  name=' + tn);
      L('    label=' + T(dbo.getValue('label')));
      L('    super=' + dbo.getValue('super_class'));
    }
    if (cands.length === 0) { L('  (none)'); }
  } catch (e3) { L('  ERROR ' + e3.message); }

  for (var k = 0; k < cands.length; k++) {
    var t = cands[k];
    L('## fields ' + t);
    try {
      var dd = new GlideRecord('sys_dictionary');
      dd.addQuery('name', t);
      dd.addQuery('active', true);
      dd.addNotNullQuery('element');
      dd.orderBy('element');
      dd.setLimit(200);
      dd.query();
      while (dd.next()) {
        var el = dd.getValue('element');
        var it = dd.getValue('internal_type');
        L('  ' + el + ' [' + it + ']');
        var ref = dd.getValue('reference');
        if (ref) { L('    ref -> ' + ref); }
        var lbl = dd.getValue('column_label');
        if (lbl) { L('    label: ' + T(lbl)); }
      }
    } catch (e4) { L('  ERROR ' + e4.message); }
    L('## choices ' + t);
    try {
      var ch = new GlideRecord('sys_choice');
      ch.addQuery('name', t);
      ch.orderBy('element');
      ch.setLimit(200);
      ch.query();
      var cn = 0;
      while (ch.next()) {
        cn++;
        var ce = ch.getValue('element');
        var cv = ch.getValue('value');
        L('  ' + ce + ' = ' + cv);
        L('    (' + T(ch.getValue('label')) + ')');
      }
      if (cn === 0) { L('  (none)'); }
    } catch (e5) { L('  ERROR ' + e5.message); }
  }

  L('## sys_user.fields');
  var uf = [
    'web_service_access_only',
    'last_login_time',
    'active',
    'locked_out'
  ];
  for (var m = 0; m < uf.length; m++) {
    try {
      var fd = new GlideRecord('sys_dictionary');
      fd.addQuery('name', 'sys_user');
      fd.addQuery('element', uf[m]);
      fd.setLimit(1);
      fd.query();
      if (fd.next()) {
        L('  ' + uf[m] + ' = ' + fd.getValue('internal_type'));
      } else {
        L('  ' + uf[m] + ' = MISSING');
      }
    } catch (e6) { L('  ERROR ' + e6.message); }
  }

  L('---END_NOWISOR_BASICAUTH_VERIFY---');
  gs.print(out.join('\n'));
})();
