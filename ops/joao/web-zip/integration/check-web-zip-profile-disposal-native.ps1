# Inert Windows-only boundary regression: no browser, credential, network or journey.
param([Parameter(Mandatory=$true)][string]$LibraryPath,[Parameter(Mandatory=$true)][ValidatePattern('^([a-f0-9]{64})$')][string]$LibrarySha256,[Parameter(Mandatory=$true)][string]$TestRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$libraryBytes=[IO.File]::ReadAllBytes($LibraryPath)
$algorithm=[Security.Cryptography.SHA256]::Create()
try{$actualHash=([BitConverter]::ToString($algorithm.ComputeHash($libraryBytes))).Replace('-','').ToLowerInvariant()}finally{$algorithm.Dispose()}
if($actualHash -cne $LibrarySha256){throw 'native-test-library-hash'}
. ([ScriptBlock]::Create([Text.UTF8Encoding]::new($false,$true).GetString($libraryBytes)))
$libraryBytes=$null
if($env:OS -cne 'Windows_NT'){throw 'native-windows-required'}
if($TestRoot -cnotmatch '^C:\\RapporLab\\runtime\\profile-disposal-test-[a-f0-9]{32}$' -or (Test-Path -LiteralPath $TestRoot)){throw 'fresh-inert-root-required'}
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$foreign='S-1-15-3-1024-3239966617-1410756637-3494353204-65451782-2225605771-3526040376-1730753648-3419555762'
$results=[Collections.Generic.List[object]]::new()
$clock=New-WebZipClock ([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()+180000)
function Require([bool]$Condition,[string]$Code){if(-not $Condition){throw $Code}}
function Expect-Rejection([scriptblock]$Action){$rejected=$false;try{& $Action}catch{$rejected=$true};Require $rejected 'expected-rejection'}
function Add-Foreign([string]$Path,[int]$Rights){
    $acl=Get-Acl -LiteralPath $Path
    $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(),0)
    $ace=[Security.AccessControl.CommonAce]::new('None','AccessAllowed',$Rights,[Security.Principal.SecurityIdentifier]::new($foreign),$false,$null)
    $descriptor.DiscretionaryAcl.InsertAce($descriptor.DiscretionaryAcl.Count,$ace)
    $bytes=[byte[]]::new($descriptor.BinaryLength);$descriptor.GetBinaryForm($bytes,0)
    $acl.SetSecurityDescriptorBinaryForm($bytes,[Security.AccessControl.AccessControlSections]::Access)
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Dacl([string]$Path){return (Get-Acl -LiteralPath $Path).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)}
function New-InertFixtureFailure($Record,[string]$ActiveCase,[string]$Stage,[int]$CasesPassed,$Ownership=@{}) {
    $failure=[InvalidOperationException]::new('native-fixture-failed')
    $caseNames=@('setup','modify','write-dac','write-owner','generic-all','reparse','hardlink','wrong-owner','generation','creation-time','open-writer','partial-failure','not-quiescent')
    $stageNames=@('setup','get_identity','configure','expect_rejection','restrict','verify','cleanup')
    $failure.Data['FixtureCase']=if($ActiveCase -cin $caseNames){$ActiveCase}else{'unknown'}
    $failure.Data['FixtureStage']=if($Stage -cin $stageNames){$Stage}else{'unknown'}
    $failure.Data['FixtureCasesPassed']=[Math]::Max(0,[Math]::Min(12,$CasesPassed))
    $frames=@([regex]::Matches([string]$Record.Exception.GetBaseException().StackTrace,'WebZipProfileHandle\.(\.ctor|Inspect|ReadSecurity|ValidateSecurity|Restrict)\(')|ForEach-Object{$_.Groups[1].Value}|Select-Object -Unique -First 8)
    $lines=@([regex]::Matches([string]$Record.ScriptStackTrace,'line\s+(\d+)')|ForEach-Object{[int]$_.Groups[1].Value}|Where-Object{$_ -ge 1 -and $_ -le 100000}|Select-Object -First 8)
    $failure.Data['NativeFrames']=[string[]]$frames
    $failure.Data['FixtureLines']=[int[]]$lines
    $closedOwnership=@{}
    foreach($key in @('profileMatches','cacheMatches','fileBefore','fileAfter','outsideFileBefore','outsideFileAfter')){
        if($Ownership.ContainsKey($key) -and $Ownership[$key] -is [bool]){$closedOwnership[$key]=$Ownership[$key]}
    }
    $failure.Data['FixtureOwnership']=$closedOwnership
    return $failure
}
function Set-InertFileOwner([string]$Path,[string]$OwnerSid){
    # Bind the two files just created by this fixture to its explicit owner.
    $acl=Get-Acl -LiteralPath $Path
    $before=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ceq $OwnerSid
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new($OwnerSid))
    Set-Acl -LiteralPath $Path -AclObject $acl
    $after=(Get-Acl -LiteralPath $Path).GetOwner([Security.Principal.SecurityIdentifier]).Value -ceq $OwnerSid
    Require $after 'fixture-file-owner-not-established'
    return @{before=$before;after=$after}
}
$activeCase='setup';$phase='setup';$ownershipEvidence=@{}
Set-WebZipPrivateDirectory $TestRoot $owner
try {
    foreach($case in @('modify','write-dac','write-owner','generic-all','reparse','hardlink','wrong-owner','generation','creation-time','open-writer','partial-failure','not-quiescent')){
        $activeCase=$case;$phase='setup';$ownershipEvidence=@{}
        $root=Join-Path $TestRoot $case;Set-WebZipPrivateDirectory $root $owner
        $profile=Join-Path $root 'profile';Set-WebZipPrivateDirectory $profile $owner
        $phase='get_identity'
        $identity=Get-WebZipProfileIdentity $profile $owner
        $phase='configure'
        $cache=Join-Path $profile 'Cache';Set-WebZipPrivateDirectory $cache $owner
        $file=Join-Path $cache 'inert.txt';[IO.File]::WriteAllText($file,'synthetic-inert-data')
        $fileOwner=Set-InertFileOwner $file $owner
        $ownershipEvidence.fileBefore=$fileOwner.before;$ownershipEvidence.fileAfter=$fileOwner.after
        $ownershipEvidence.profileMatches=(Get-Acl -LiteralPath $profile).GetOwner([Security.Principal.SecurityIdentifier]).Value -ceq $owner
        $ownershipEvidence.cacheMatches=(Get-Acl -LiteralPath $cache).GetOwner([Security.Principal.SecurityIdentifier]).Value -ceq $owner
        Require ($ownershipEvidence.profileMatches -and $ownershipEvidence.cacheMatches) 'fixture-directory-owner-not-established'
        $outside=Join-Path $root 'outside';Set-WebZipPrivateDirectory $outside $owner
        # An unprotected target makes accidental junction propagation observable.
        $outsideAcl=Get-Acl -LiteralPath $outside
        $outsideAcl.SetAccessRuleProtection($false,$true)
        Set-Acl -LiteralPath $outside -AclObject $outsideAcl
        $outsideFile=Join-Path $outside 'inert.txt';[IO.File]::WriteAllText($outsideFile,'synthetic-outside-sentinel')
        $outsideFileOwner=Set-InertFileOwner $outsideFile $owner
        $ownershipEvidence.outsideFileBefore=$outsideFileOwner.before;$ownershipEvidence.outsideFileAfter=$outsideFileOwner.after
        $original=Dacl $outside;$originalFile=Dacl $outsideFile
        $writer=$null;$link=$null
        try {
            switch($case){
                'modify' {Add-Foreign $cache 1245631}
                'write-dac' {Add-Foreign $cache 0x40000}
                'write-owner' {Add-Foreign $cache 0x80000}
                'generic-all' {Add-Foreign $cache 0x10000000}
                'reparse' {$link=Join-Path $profile 'junction';New-Item -ItemType Junction -Path $link -Target $outside|Out-Null}
                'hardlink' {$link=Join-Path $profile 'hardlink.txt';New-Item -ItemType HardLink -Path $link -Target $outsideFile|Out-Null}
                'generation' {
                    [IO.Directory]::Move($profile,(Join-Path $root 'previous-profile'))
                    Set-WebZipPrivateDirectory $profile $owner;Set-WebZipPrivateDirectory $cache $owner
                }
                'creation-time' {[IO.Directory]::SetCreationTimeUtc($profile,(Get-Item -LiteralPath $profile).CreationTimeUtc.AddSeconds(-30))}
                'open-writer' {$writer=[IO.File]::Open($file,'Open','Write','ReadWrite,Delete')}
                'partial-failure' {Add-Foreign $profile 1245631;Add-Foreign $cache 0x40000}
            }
            if($case -eq 'modify'){
                $phase='expect_rejection'
                Expect-Rejection {Assert-WebZipPath $cache $owner}
                $phase='restrict'
                Protect-WebZipProfileForDisposal $root $profile $owner $identity $clock $true
                $phase='verify'
                Assert-WebZipPath $file $owner
                $acl=Get-Acl -LiteralPath $cache
                Require $acl.AreAccessRulesProtected 'dacl-unprotected'
                Require (@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])).Count -eq 3) 'dacl-not-three-principals'
                Require ((Get-Content -LiteralPath $file -Raw) -ceq 'synthetic-inert-data') 'fixture-content-changed'
            }else{
                $phase='expect_rejection'
                $before=Dacl $cache
                if($case -eq 'wrong-owner'){
                    Expect-Rejection {$handle=Open-WebZipProfileHandle $profile 'S-1-5-18' $identity;try{$handle.Restrict()}finally{$handle.Dispose()}}
                }else{
                    Expect-Rejection {Protect-WebZipProfileForDisposal $root $profile $owner $identity $clock ($case -ne 'not-quiescent')}
                }
                if($case -in @('write-dac','write-owner','generic-all','partial-failure')){
                    Require ((Dacl $cache) -ceq $before) 'unsafe-child-dacl-modified'
                }
                if($case -eq 'partial-failure'){
                    Assert-WebZipPath $profile $owner
                    Expect-Rejection {Assert-WebZipPath $cache $owner}
                }
            }
            $phase='verify'
            Require ((Dacl $outside) -ceq $original) 'outside-directory-dacl-changed'
            Require ((Dacl $outsideFile) -ceq $originalFile) 'outside-file-dacl-changed'
            $results.Add(@{case=$case;passed=$true;ownership=$ownershipEvidence})
        }finally{
            $originalPhase=$phase;$phase='cleanup'
            if($writer){$writer.Dispose()}
            if($link -and (Test-Path -LiteralPath $link)){
                # Remove only this fixture's link; never recurse through a junction.
                if($case -eq 'reparse'){[IO.Directory]::Delete($link)}else{[IO.File]::Delete($link)}
            }
            # These exact fixture-owned objects may retain deliberately hostile ACEs.
            foreach($directory in @($profile,$cache)){
                $acl=Get-Acl -LiteralPath $directory
                $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(),0)
                for($index=$descriptor.DiscretionaryAcl.Count-1;$index -ge 0;$index--){
                    $ace=$descriptor.DiscretionaryAcl[$index]
                    if($ace -is [Security.AccessControl.CommonAce] -and $ace.SecurityIdentifier.Value -ceq $foreign){$descriptor.DiscretionaryAcl.RemoveAce($index)}
                }
                $bytes=[byte[]]::new($descriptor.BinaryLength);$descriptor.GetBinaryForm($bytes,0)
                $acl.SetSecurityDescriptorBinaryForm($bytes,[Security.AccessControl.AccessControlSections]::Access)
                Set-Acl -LiteralPath $directory -AclObject $acl
            }
            $phase=$originalPhase
        }
    }
    @{schema=1;scope='inert-native-profile-disposal';cases=$results;passed=$results.Count}|ConvertTo-Json -Depth 5 -Compress
}catch{
    throw (New-InertFixtureFailure $_ $activeCase $phase $results.Count $ownershipEvidence)
}finally{
    # Failure to remove an inert fixture is a test failure, never silently ignored.
    Remove-WebZipTree $TestRoot $owner $clock
}
