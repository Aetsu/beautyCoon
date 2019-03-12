###########################################################################################
##                                                                                       ##
##          BeautyCoon v0.2                                                              ##
##          by @aetsu - 2019              												 ##
##                                                                                       ##
##          This program is free software: you can redistribute it and/or modify         ##
##          it under the terms of the GNU General Public License as published by         ##
##          the Free Software Foundation, either version 2 of the License, or            ##
##          (at your option) any later version.                                          ##
##                                                                                       ##
##          This program is distributed in the hope that it will be useful,              ##
##          but WITHOUT ANY WARRANTY; without even the implied warranty of               ##
##          MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                ##
##          GNU General Public License for more details.                                 ##
##                                                                                       ##
##          You should have received a copy of the GNU General Public License            ##
##          along with this program.  If not, see <http://www.gnu.org/licenses/>.        ##
##                                                                                       ##
###########################################################################################

import dotnessus_v2
import sys
import html


def parseNessusReport(nessusFile):
	"""
	Read Nessus file
	:param nessusFile: Nessus file
	:return: Nessus targets
	"""
	rpt = dotnessus_v2.Report()
	rpt.parse(nessusFile)
	return rpt


def saveBootstrap(dParams, outputName='output.html'):
	"""
	Save the bootstrap template
		:param dParams: Dictionary with parameters to replace in the template
		:param outputName: Output report name. Default: output.html 
	"""
	template = ''
	with open('template.html', 'r') as rf:
		template = rf.read()
	for k, v in dParams.items():
		template = template.replace(
			'{{' + k + '}}', v)

	with open(outputName, 'w') as wf:
		wf.write(template)


def vulnList(dVulns, risk, data_target='vulnProps'):
	"""
	List of vulnerabilities filtered by risk
		:param dVulns: dictionary with vulnerabilities
		:param risk: risk filter
		:param data_target='vulnProps': prefix identifier 
	"""
	vulnerabilityList_str = ''
	label = ""
	for k, v in dVulns.items():
		if str(v['risk_factor']).lower() == "critical":
			label = "label-danger"
		elif v['risk_factor'].lower() == "high":
			label = "label-warning"
		elif v['risk_factor'].lower() == "medium":
			label = "label-primary"
		elif v['risk_factor'].lower() == "low":
			label = "label-success"
		else:
			label = "label-info"
		if str(v['risk_factor']).lower() == risk:
			hostList_str = ''
			if 'hosts' in v:
				for host in v['hosts']:
					hostList_str += '<tr><td>' + host[0] + '</td><td>' + host[3] + \
						'</td><td>' + host[1] + '</td><td>' + \
						host[2] + '</td></tr>'
			vulnerabilityList_str += '<tr><td><span class="label ' + label + '">' + \
				v['risk_factor'] + '</span></td>' + \
				'<td><button type="button" class="btn btn-light" data-toggle="collapse" data-target="#' + data_target + \
				v['plugin_id'] + '">Info</button></td>' + \
				'<td>' + v['plugin_name'] + '<div id="' + data_target + v['plugin_id'] + '" class="collapse">' + \
				'<br><p><b>CVSSv2:</b><br>' + \
				str(v['cvss_base_score']) + \
				'</p>' + \
				'<p><b>CVSSv2 vector:</b><br>' + \
				str(v['cvss_vector']) + \
				'</p>' + \
				'<p><b>CVSSv3:</b><br>' + \
				str(v['cvss3_base_score']) + \
				'</p>' + \
				'<p><b>CVSSv3 vector:</b><br>' + \
				str(v['cvss3_vector']) + \
				'</p>' + \
				'<br><p><b>Description:</b><br>' + \
				v['description'].replace('\n', '<br>') + \
				'</p>' + \
				'<br><p><b>Solution:</b><br>' + \
				v['solution'].replace('\n', '<br>') + \
				'</p>' + \
				'<br><p><b>Output:</b><br>' + \
				'<div class="panel panel-default"><div class="panel-body">' + \
				html.escape(str(v['plugin_output'])).replace('\n', '<br>') + '</div></div>' + \
				'</p>' + \
                '<p><b>Exploit:</b><br>' + \
                str(v['exploit_available']) + \
                '</p><br>'

			if 'hosts' in v:
				vulnerabilityList_str += '<div class="table-responsive"><table class="table table-hover">' + \
					'<thead><tr><th>Host</th><th>Name</th><th>Port</th><th>Protocol</th></tr></thead>' + \
					hostList_str + \
					'</table></div>' + \
					'</div>' + \
					'</td><td><span class="badge">' + \
					str(len(v['hosts'])) + \
					'</span></td></tr>'
			else:
				vulnerabilityList_str += '</div>'

	return vulnerabilityList_str


def analizeFile(targets):
	"""
	Analyzes the targets 
		:param targets: target list
	"""
	dAux	 = {}
	for elem in targets:
		for v in elem.vulns:
			if v.get('plugin_id') in dAux:
				auxHosts = dAux[v.get('plugin_id')]['hosts']
				auxHosts.append(
					[elem.name, v.port, v.protocol, elem.get_name()])
				dAux[v.get('plugin_id')]['hosts'] = auxHosts
			else:
				if v.get('plugin_output') is not None:
					pOutput = v.get('plugin_output').replace('meta http-equiv="refresh"', 'meta http-equiv=""')
				else:
					pOutput = ''
				dAux[v.get("plugin_id")] = {
					"plugin_id": v.get("plugin_id"),
					"plugin_name": v.get('plugin_name'),
					"hosts": [[elem.name, v.port, v.protocol, elem.get_name()]],
					"risk_factor": v.get('risk_factor'),
					"description": v.get('description'),
					"solution": v.get('solution'),
					"see_also": v.get('see_also'),
					"cvss_vector": v.get('cvss_vector'),
					"cvss_base_score": v.get('cvss_base_score'),
					"cvss3_vector": v.get('cvss3_vector'),
					"cvss3_base_score": v.get('cvss3_base_score'),
					"plugin_output": pOutput,
					"cve": v.get('cve'),
					"cpe": v.get('cpe'),
					"exploit_available": v.get('exploit_available')}
	return dAux


def getHostsServices(targets):
	"""
	Get the list of hosts, their ports and services
		:param targets: target list
	"""
	dRes = {}
	hostsStr = ''
	for t in targets:
		if not t.name in dRes:
			dRes[t.name] = {'name': t.get_name()}
		for v in t.vulns:
			if v.plugin_id == '11219':
				dRes[t.name][int(v.port)] = [v.protocol, v.svc_name]
	for k, v in dRes.items():
		for port, infoPort in v.items():
			if port != 'name':
				hostsStr += '<tr><td>' + k + '</td><td>' + v['name'] + '</td>' + \
					'<td>' + str(port) + '</td><td>' + \
					infoPort[0] + '</td><td>' + infoPort[1] + '</td></tr>'

	return hostsStr


def getHostsVulnerabilities(targets):
	"""
	Gets all vulnerabilities from each host
		:param targets: target list
	"""
	dRes = {}
	hostsStr = ''
	for t in targets:
		dAux = {}
		for v in t.vulns:
			if v.get('risk_factor').lower() != "none":
				dAux[v.get("plugin_id")] = {
					"plugin_id": v.get("plugin_id"),
					"plugin_name": v.get('plugin_name'),
					"vulnerability_port": v.get("port"),
					"vulnerability_protocol": v.get("protocol"),
					"risk_factor": v.get('risk_factor'),
					"description": v.get('description'),
					"solution": v.get('solution'),
					"see_also": v.get('see_also'),
					"cvss_vector": v.get('cvss_vector'),
					"cvss_base_score": v.get('cvss_base_score'),
					"cvss3_vector": v.get('cvss3_vector'),
					"cvss3_base_score": v.get('cvss3_base_score'),
					"plugin_output": v.get('plugin_output'),
					"cve": v.get('cve'),
					"cpe": v.get('cpe'),
					"exploit_available": v.get('exploit_available')}
		dRes[t.name] = {'name': t.get_name(), 'vulns': dAux}

	for h, info in dRes.items():
		hostsStr += '<div class="panel panel-default"><div class="panel-heading">' + \
			h + '</div>' + \
			'<div class="panel-body">' + \
			'<table class="table table-hover">' + \
			'<thead><tr><th>Risk</th><th>Info</th><th>Title</th></thead></tr><tbody>' + \
			vulnList(info['vulns'], 'critical', 'vulnHostPropsC' + h.replace('.', '')) + \
			vulnList(info['vulns'], 'high', 'vulnHostPropsH' + h.replace('.', '')) + \
			vulnList(info['vulns'], 'medium', 'vulnHostPropsM' + h.replace('.', '')) + \
			vulnList(info['vulns'], 'low', 'vulnHostPropsL' + h.replace('.', '')) + \
			'</tbody></table></div></div>'
	return hostsStr

def percentage(part, whole):
	return 100 * float(part)/float(whole)


def main(filename):
	report = parseNessusReport(filename)
	dInfo = analizeFile(report.targets)
	cVulns = sum(1 for x in dInfo.values()
				 if x['risk_factor'].lower() == 'critical')
	hVulns = sum(1 for x in dInfo.values()
				 if x['risk_factor'].lower() == 'high')
	mVulns = sum(1 for x in dInfo.values()
				 if x['risk_factor'].lower() == 'medium')
	lVulns = sum(1 for x in dInfo.values()
				 if x['risk_factor'].lower() == 'low')
	pcVulns = (percentage(cVulns, cVulns + hVulns + mVulns + lVulns))
	phVulns = percentage(hVulns, cVulns + hVulns + mVulns + lVulns)
	pmVulns = percentage(mVulns, cVulns + hVulns + mVulns + lVulns)
	plVulns = percentage(lVulns, cVulns + hVulns + mVulns + lVulns)
	strCritical = vulnList(dInfo, 'critical')
	strHigh = vulnList(dInfo, 'high')
	strMedium = vulnList(dInfo, 'medium')
	strLow = vulnList(dInfo, 'low')
	strInfo = vulnList(dInfo, 'none')
	strHostVulns = getHostsVulnerabilities(report.targets)
	strOpenServices = getHostsServices(report.targets)
	dParams = {
		'reportName': report.name,
		'cVulns': str(cVulns),
		'hVulns': str(hVulns),
		'mVulns': str(mVulns),
		'lVulns': str(lVulns),
		'pcVulns': str(pcVulns),
		'phVulns': str(phVulns),
		'pmVulns': str(pmVulns),
		'plVulns': str(plVulns),
		'criticalVulnerability': strCritical,
		'highVulnerability': strHigh,
		'mediumVulnerability': strMedium,
		'lowVulnerability': strLow,
		'infoVulnerability': strInfo,
		'vulnerabilitiesHost': strHostVulns,
		'openServices': strOpenServices
	}
	saveBootstrap(dParams, sys.argv[1].replace('.nessus', '.html'))


if __name__ == '__main__':
	banner = '''

	▄▄▄▄   ▓█████ ▄▄▄       █    ██ ▄▄▄█████▓▓██   ██▓ ▄████▄   ▒█████   ▒█████   ███▄    █
	▓█████▄ ▓█   ▀▒████▄     ██  ▓██▒▓  ██▒ ▓▒ ▒██  ██▒▒██▀ ▀█  ▒██▒  ██▒▒██▒  ██▒ ██ ▀█   █
	▒██▒ ▄██▒███  ▒██  ▀█▄  ▓██  ▒██░▒ ▓██░ ▒░  ▒██ ██░▒▓█    ▄ ▒██░  ██▒▒██░  ██▒▓██  ▀█ ██▒
	▒██░█▀  ▒▓█  ▄░██▄▄▄▄██ ▓▓█  ░██░░ ▓██▓ ░   ░ ▐██▓░▒▓▓▄ ▄██▒▒██   ██░▒██   ██░▓██▒  ▐▌██▒
	░▓█  ▀█▓░▒████▒▓█   ▓██▒▒▒█████▓   ▒██▒ ░   ░ ██▒▓░▒ ▓███▀ ░░ ████▓▒░░ ████▓▒░▒██░   ▓██░
	░▒▓███▀▒░░ ▒░ ░▒▒   ▓▒█░░▒▓▒ ▒ ▒   ▒ ░░      ██▒▒▒ ░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░▒░▒░ ░ ▒░   ▒ ▒
	▒░▒   ░  ░ ░  ░ ▒   ▒▒ ░░░▒░ ░ ░     ░     ▓██ ░▒░   ░  ▒     ░ ▒ ▒░   ░ ▒ ▒░ ░ ░░   ░ ▒░
	░    ░    ░    ░   ▒    ░░░ ░ ░   ░       ▒ ▒ ░░  ░        ░ ░ ░ ▒  ░ ░ ░ ▒     ░   ░ ░
	░         ░  ░     ░  ░   ░               ░ ░     ░ ░          ░ ░      ░ ░           ░
		░                                    ░ ░     ░

	'''
	print(banner)
	print()
	print('										BeautyCoon - v 0.2')
	print(' 												@aetsu')
	print()
	if len(sys.argv) != 2:
		print(' [><] Usage:')
		print('		python3 ' + sys.argv[0] + ' <file.nessus>')
	else:
		main(sys.argv[1])
		print(' [>] Input file: ' + sys.argv[1])
		print(' [<] Output file: ' + sys.argv[1].replace('.nessus', '.html'))	
	print()