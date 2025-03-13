# Name of the VPN connexion
$vpnName="MSFTVPN-Manual"


$conn=$(Get-VpnConnection -Name $vpnName).ConnectionStatus
if ($conn -eq 'Disconnected') {
    rasdial $vpnName
}

Write-Host "Sleeping..."    
sleep 10

Write-Host "Done."