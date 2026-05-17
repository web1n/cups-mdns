//
// Copyright (c) 2026
//

'use strict';
'require form';
'require rpc';
'require uci';
'require view';
'require network';

const callHostHints = rpc.declare({
	object: 'luci-rpc',
	method: 'getHostHints',
	expect: { '': {} }
});

return view.extend({
	load() {
		return Promise.all([
			L.resolveDefault(callHostHints(), {}),
			L.resolveDefault(network.getDevices(), []),
		]);
	},

	render(data) {
		let hosts = data[0] || {};
		let devs = data[1] || [];

		let ipaddrs = {};
		Object.keys(hosts).forEach(function(mac) {
			L.toArray(hosts[mac].ipaddrs || hosts[mac].ipv4).forEach(function(ip) {
				ipaddrs[ip] = mac;
			});
		});

		let m, s, o;

		m = new form.Map('cups-mdns', _('CUPS mDNS'),
			_('Poll a CUPS server via IPP and advertise printers through mDNS.') +
			'<br />' +
			_('Note: may conflict with umdns or avahi, please disable them first.'));

		s = m.section(form.NamedSection, 'config', 'config',
			_('General Settings'),
			_('Basic service configuration.'));

		o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.rmempty = false;

		o = s.option(form.Value, 'cups_host', _('CUPS Server'),
			_('IPv4 address of the CUPS server.'));
		o.datatype = 'ipaddr("nomask")';
		o.rmempty = false;
		L.sortedKeys(ipaddrs, null, 'addr').forEach(function(ip) {
			o.value(ip, '%s (%s)'.format(ip, ipaddrs[ip]));
		});

		o = s.option(form.Value, 'cups_port', _('CUPS Port'),
			_('Port number of the CUPS server.'));
		o.datatype = 'port';
		o.rmempty = false;

		o = s.option(form.Value, 'hostname', _('mDNS Hostname'),
			_('Hostname advertised via mDNS (without .local suffix).'));
		o.placeholder = 'cups-proxy';
		o.rmempty = false;

		o = s.option(form.ListValue, 'bind_interface', _('Bind Interface'),
			_('Network interface for mDNS multicast. Leave empty for automatic detection.'));
		o.rmempty = true;
		devs.forEach(function(dev) {
			o.value(dev.getName(), dev.getName());
		});

		o = s.option(form.Value, 'poll_interval', _('Poll Interval'),
			_('Seconds between CUPS printer list queries.') +
			'<br />' + _('Range: 5–600 seconds.'));
		o.datatype = 'range(5, 600)';
		o.placeholder = '360';

		o = s.option(form.Value, 'timeout', _('Request Timeout'),
			_('HTTP timeout in seconds for CUPS requests.'));
		o.datatype = 'range(1, 300)';
		o.placeholder = '5';
		o.rmempty = false;

		o = s.option(form.Flag, 'debug', _('Debug Logging'),
			_('Enable verbose mDNS debug output to system log.'));
		o.rmempty = false;

		o = s.option(form.Flag, 'loopback', _('Multicast Loopback'),
			_('Enable multicast loopback (disabled by default per RFC 6762).') +
			'<br />' + _('When enabled, services are also visible via dns-sd on this device.'));
		o.rmempty = false;

		return m.render();
	}
});
