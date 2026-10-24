<?php
declare(strict_types=1);

/**
 * Normalización de mensajes Syslog de MikroTik RouterOS (v6.49) al formato de eventos de SecureWatch.
 *
 * Acepta los dos formatos que RouterOS puede enviar:
 *   bsd-syslog=no :  <PRI>topics mensaje
 *   bsd-syslog=yes:  <PRI>Mmm dd hh:mm:ss host topics mensaje
 *
 * Devuelve un arreglo con: event_type, description, result, severity, ip, username,
 * method, endpoint, request_data y metadata. Nunca lanza excepciones: si el mensaje
 * no coincide con ningún patrón conocido se registra como ROUTER_LOG.
 */

const ROUTEROS_TOPICS = [
    'system','info','error','warning','critical','debug','account','firewall','dhcp','interface','script',
    'wireless','ppp','pppoe','ovpn','l2tp','pptp','sstp','hotspot','ospf','bgp','rip','route','dns','ntp',
    'e-mail','web-proxy','caps','manager','packet','raw','read','write','ipsec','bridge','stp','lte','health',
    'watchdog','ssh','telnet','async','certificate','radius','snmp','upnp','vrrp','store','event','backup',
];

function routeros_parse(string $raw, string $senderIp): array
{
    $line = trim(str_replace(["\r", "\n", "\0"], ' ', $raw));
    $meta = ['transport' => 'syslog_udp', 'sender_ip' => $senderIp, 'raw' => mb_substr($line, 0, 1000)];

    // 1. Prioridad <PRI>
    $sysSeverity = null;
    if (preg_match('/^<(\d{1,3})>/', $line, $m)) {
        $pri = (int)$m[1];
        $meta['facility'] = intdiv($pri, 8);
        $sysSeverity = $pri % 8;
        $meta['syslog_severity'] = $sysSeverity;
        $line = substr($line, strlen($m[0]));
    }

    // 2. Encabezado BSD opcional: "Oct 24 00:15:01 MikroTik "
    if (preg_match('/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+/', $line, $m)) {
        $meta['router_time'] = $m[1];
        $meta['router_host'] = $m[2];
        $line = substr($line, strlen($m[0]));
    }

    // 3. Temas de RouterOS: "system,error,critical "
    $topics = [];
    if (preg_match('/^([a-z0-9-]+(?:,[a-z0-9-]+)*)\s+/', $line, $m)) {
        $parts = explode(',', $m[1]);
        if (!array_diff($parts, ROUTEROS_TOPICS)) {
            $topics = $parts;
            $line = substr($line, strlen($m[0]));
        }
    }
    $meta['topics'] = implode(',', $topics);
    $msg = trim($line);

    $out = [
        'event_type' => 'ROUTER_LOG',
        'description' => mb_substr($msg, 0, 255),
        'result' => 'INFO',
        'severity' => (in_array('critical', $topics, true) || in_array('error', $topics, true) || ($sysSeverity !== null && $sysSeverity <= 3)) ? 'medium' : 'low',
        'ip' => $senderIp,
        'username' => null,
        'method' => null,
        'endpoint' => null,
        'request_data' => null,
        'metadata' => $meta,
    ];
    $ipv4 = '((?:\d{1,3}\.){3}\d{1,3})';

    // 4a. Autenticación en el router (WinBox, SSH, Telnet, WebFig, API, FTP, consola).
    //     El origen puede ser una IP, una MAC (WinBox por MAC) o no venir ("via local").
    $mac = '([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})';
    $auth = [
        ['/login failure for user (\S+)(?: from (\S+))? via (\S+)/i', 'LOGIN_FAILED', 'FAILED', 'medium', 'Login fallido en el router'],
        ['/user (\S+) logged in(?: from (\S+))? via (\S+)/i', 'LOGIN_SUCCESS', 'SUCCESS', 'low', 'Inicio de sesión en el router'],
        ['/user (\S+) logged out(?: from (\S+))? via (\S+)/i', 'LOGOUT', 'SUCCESS', 'low', 'Cierre de sesión en el router'],
    ];
    foreach ($auth as [$re, $type, $result, $sev, $text]) {
        if (!preg_match($re, $msg, $m)) continue;
        $origin = $m[2] ?? '';
        $ip = $senderIp;
        $desc = $text . ' vía ' . $m[3];
        if (preg_match('/^' . $ipv4 . '$/', $origin)) {
            $ip = $origin;
        } elseif (preg_match('/^' . $mac . '$/', $origin)) {
            $out['metadata']['src_mac'] = strtoupper($origin);
            $desc .= ' (por MAC ' . strtoupper($origin) . ')';
        } elseif ($origin === '') {
            $desc .= ' (sesión local del router)';
        }
        $out = array_merge($out, ['event_type'=>$type,'result'=>$result,'severity'=>$sev,'username'=>$m[1],'ip'=>$ip,'description'=>$desc]);
        $out['metadata']['service'] = $m[3];
        return $out;
    }

    // 4b. Registro del firewall: "[prefijo] input: in:ether6 out:(unknown 0), src-mac ..., proto TCP (SYN), 1.2.3.4:5555->5.6.7.8:23, len 52"
    if (preg_match('/^(.*?)\b(input|forward|output|prerouting|postrouting|srcnat|dstnat):\s+in:(\S+)\s+out:([^,]+),.*?proto\s+([A-Za-z0-9]+)(?:\s+\(([^)]*)\))?,\s+' . $ipv4 . '(?::(\d+))?->' . $ipv4 . '(?::(\d+))?/', $msg, $m)) {
        $prefix = trim($m[1], " :");
        $chain = $m[2];
        $proto = strtoupper($m[5]);
        $flags = $m[6] ?? '';
        $src = $m[7]; $sport = $m[8] ?? '';
        $dst = $m[9]; $dport = $m[10] ?? '';
        $dropped = (bool)preg_match('/drop|bloq|reject|deny/i', $prefix);
        $out = array_merge($out, [
            'event_type' => 'FIREWALL_CONNECTION',
            'result' => $dropped ? 'DROPPED' : 'LOGGED',
            'severity' => 'low',
            'ip' => $src,
            'method' => $proto,
            'endpoint' => $proto . '/' . ($dport !== '' ? $dport : ($flags ?: '-')),
            'description' => mb_substr(($dropped ? 'Bloqueado ' : 'Conexión ') . $proto . ' ' . $src . ($sport !== '' ? ':' . $sport : '')
                . ' → ' . $dst . ($dport !== '' ? ':' . $dport : '') . ' (' . $chain . ', in:' . $m[3] . ')' . ($prefix !== '' ? ' [' . $prefix . ']' : ''), 0, 255),
        ]);
        $out['metadata'] += ['chain'=>$chain,'in_interface'=>$m[3],'out_interface'=>trim($m[4]),'protocol'=>$proto,'flags'=>$flags,
            'src_ip'=>$src,'src_port'=>$sport,'dst_ip'=>$dst,'dst_port'=>$dport,'log_prefix'=>$prefix];
        return $out;
    }

    // 4c. DHCP: "defconf assigned 192.168.88.253 to D4:81:D7:6D:7C:22"
    if (preg_match('/(\S+) (assigned|deassigned) ' . $ipv4 . ' (?:to|from) ([0-9A-Fa-f:]{17})/', $msg, $m)) {
        $assigned = strtolower($m[2]) === 'assigned';
        $out = array_merge($out, ['event_type'=>$assigned ? 'DHCP_LEASE' : 'DHCP_RELEASE','result'=>'INFO','severity'=>'low','ip'=>$m[3],
            'description'=>($assigned ? 'DHCP asignó ' : 'DHCP liberó ') . $m[3] . ($assigned ? ' a ' : ' de ') . strtoupper($m[4]) . ' (' . $m[1] . ')']);
        $out['metadata'] += ['dhcp_server'=>$m[1],'mac'=>strtoupper($m[4])];
        return $out;
    }

    // 4d. Enlace de interfaz: "ether6 link up (speed 100M, full duplex)" / "ether6 link down"
    if (preg_match('/^(\S+) link (up|down)\b/i', $msg, $m)) {
        $up = strtolower($m[2]) === 'up';
        $out = array_merge($out, ['event_type'=>$up ? 'INTERFACE_UP' : 'INTERFACE_DOWN','result'=>'INFO','severity'=>$up ? 'low' : 'medium',
            'endpoint'=>$m[1],'description'=>'Interfaz ' . $m[1] . ($up ? ' conectada' : ' desconectada')]);
        $out['metadata']['interface'] = $m[1];
        return $out;
    }

    // 4e. Cambios de configuración: "filter rule added by admin", "user changed by admin"
    if (preg_match('/^(.+?) (added|removed|changed|moved|enabled|disabled) by (.+)$/i', $msg, $m)) {
        $actor = trim($m[3]);
        $user = $actor;
        $ip = $senderIp;
        if (preg_match('/([A-Za-z0-9_.-]+)@' . $ipv4 . '/', $actor, $a)) { $user = $a[1]; $ip = $a[2]; }
        elseif (preg_match('/^([A-Za-z0-9_.-]+)/', $actor, $a)) { $user = $a[1]; }
        $out = array_merge($out, ['event_type'=>'ROUTER_CONFIG_CHANGE','result'=>'SUCCESS','severity'=>'medium','username'=>mb_substr($user,0,60),'ip'=>$ip,
            'description'=>mb_substr('Configuración del router: ' . $m[1] . ' ' . strtolower($m[2]) . ' por ' . $actor, 0, 255)]);
        $out['metadata']['change'] = $m[1];
        return $out;
    }

    return $out;
}
