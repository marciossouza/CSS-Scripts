Param(
 [Parameter(Mandatory=$true, HelpMessage="Must be a file generated using csexport 'Name of Connector' export.xml /f:x)")]
 [string]$xmltoimport="%temp%\exportedStage1a.xml",
 [Parameter(Mandatory=$false, HelpMessage="Maximum number of users per output file")][int]$batchsize=1000,
 [Parameter(Mandatory=$false, HelpMessage="Show console output")][bool]$showOutput=$false
)

#LINQ isn't loaded automatically, so force it
[Reflection.Assembly]::Load("System.Xml.Linq, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089") | Out-Null

[int]$count=1
[int]$outputfilecount=1
[array]$objOutputUsers=@()

#XML must be generated using "csexport "Name of Connector" export.xml /f:x"
write-host "Importing XML" -ForegroundColor Yellow

#XmlReader.Create won't properly resolve the file location,
#so expand and then resolve it
$resolvedXMLtoimport=Resolve-Path -Path ([Environment]::ExpandEnvironmentVariables($xmltoimport))

#use an XmlReader to deal with even large files
$result=$reader = [System.Xml.XmlReader]::Create($resolvedXMLtoimport) 
$result=$reader.ReadToDescendant('cs-object')
if($result)
{
 do 
 {
  #create the object placeholder
  #adding them up here means we can enforce consistency
  $objOutputUser=New-Object psobject
  Add-Member -InputObject $objOutputUser -MemberType NoteProperty -Name ID -Value ""
  Add-Member -InputObject $objOutputUser -MemberType NoteProperty -Name Type -Value ""
  Add-Member -inputobject $objOutputUser -MemberType NoteProperty -Name DN -Value ""
  Add-Member -inputobject $objOutputUser -MemberType NoteProperty -Name operation -Value ""
  Add-Member -inputobject $objOutputUser -MemberType NoteProperty -Name UPN -Value ""
  Add-Member -inputobject $objOutputUser -MemberType NoteProperty -Name displayName -Value ""
  Add-Member -inputobject $objOutputUser -MemberType NoteProperty -Name sourceAnchor -Value ""
  Add-Member -inputobject $objOutputUser -MemberType NoteProperty -Name alias -Value ""
  Add-Member -inputobject $objOutputUser -MemberType NoteProperty -Name primarySMTP -Value ""
  Add-Member -inputobject $objOutputUser -MemberType NoteProperty -Name onPremisesSamAccountName -Value ""
  Add-Member -inputobject $objOutputUser -MemberType NoteProperty -Name mail -Value ""

$user = [System.Xml.Linq.XElement]::ReadFrom($reader)
  if ($showOutput) {Write-Host Found an exported object... -ForegroundColor Green}

#object id
  $outID=$user.Attribute('id').Value
  if ($showOutput) {Write-Host ID: $outID}
  $objOutputUser.ID=$outID

#object type
  $outType=$user.Attribute('object-type').Value
  if ($showOutput) {Write-Host Type: $outType}
  $objOutputUser.Type=$outType

#dn
  $outDN= $user.Element('unapplied-export').Element('delta').Attribute('dn').Value
  if ($showOutput) {Write-Host DN: $outDN}
  $objOutputUser.DN=$outDN

#mail
  $outMail= $user.Attribute('mail').Value
  if ($showOutput) {Write-Host Mail: $outMail}
  $objOutputUser.mail=$outMail

#operation
  $outOperation= $user.Element('unapplied-export').Element('delta').Attribute('operation').Value
  if ($showOutput) {Write-Host Operation: $outOperation}
  $objOutputUser.operation=$outOperation

#now that we have the basics, go get the details

foreach ($attr in $user.Element('unapplied-export-hologram').Element('entry').Elements("attr"))
  {
   $attrvalue=$attr.Attribute('name').Value
   $internalvalue= $attr.Element('value').Value

switch ($attrvalue)
   {
    "userPrincipalName"
    {
     if ($showOutput) {Write-Host UPN: $internalvalue}
     $objOutputUser.UPN=$internalvalue
    }
    "displayName"
    {
     if ($showOutput) {Write-Host displayName: $internalvalue}
     $objOutputUser.displayName=$internalvalue
    }
    "sourceAnchor"
    {
     if ($showOutput) {Write-Host sourceAnchor: $internalvalue}
     $objOutputUser.sourceAnchor=$internalvalue
    }
    "alias"
    {
     if ($showOutput) {Write-Host alias: $internalvalue}
     $objOutputUser.alias=$internalvalue
    }
    "proxyAddresses"
    {
     if ($showOutput) {Write-Host primarySMTP: ($internalvalue -replace "SMTP:","")}
     $objOutputUser.primarySMTP=$internalvalue -replace "SMTP:",""
    }
   }
  }

$objOutputUsers += $objOutputUser

Write-Progress -activity "Processing ${xmltoimport} in batches of ${batchsize}" -status "Batch ${outputfilecount}: " -percentComplete (($objOutputUsers.Count / $batchsize) * 100)

#every so often, dump the processed users in case we blow up somewhere
  if ($count % $batchsize -eq 0)
  {
   Write-Host Hit the maximum users processed without completion... -ForegroundColor Yellow

#export the collection of users as a CSV
   Write-Host Writing processedusers${outputfilecount}.csv -ForegroundColor Yellow
   $objOutputUsers | Export-Csv -path processedusers${outputfilecount}.csv -NoTypeInformation

#increment the output file counter
   $outputfilecount+=1

#reset the collection and the user counter
   $objOutputUsers = $null
   $count=0
  }

$count+=1

#need to bail out of the loop if no more users to process
  if ($reader.NodeType -eq [System.Xml.XmlNodeType]::EndElement)
  {
   break
  }

} while ($reader.Read)

#need to write out any users that didn't get picked up in a batch of 1000
 #export the collection of users as CSV
 Write-Host Writing processedusers${outputfilecount}.csv -ForegroundColor Yellow
 $objOutputUsers | Export-Csv -path processedusers${outputfilecount}.csv -NoTypeInformation
}
else
{
 Write-Host "Imported XML file is empty. No work to do." -ForegroundColor Red
}