## This is an AWS-provided set of scripting and logic in which one can run against Windows hosts on any platform. This will enabled you to measure, in depth, how the disks work, and get an idea of the type of sizing and performance characteristics of each server's disk needs. The main takeaway from this script's output is to  build an understanding of the customer / partner's workloads, and determine what kind of disk performance they're going to need in order to meet their same or better performance -as a starting point- for their migration. Many of the parameters and and options to select are customiziable, so please be sure to adjust as needed as you go. 


## In the sections below, we're setting parameters on how to build the test suite, starting with what we're naming the test file. Feel free to rename as you wish. 
Param( 
[parameter(mandatory=$False,HelpMessage='Name of test file')] 
[ValidateLength(2,30)] 
$TestFileName = "test.dat",

## Here, we're establishing and setting the test's base file size. Default is 1GB, and can scale as defined in the options. If you want to change it, feel free. 
[parameter(mandatory=$False,HelpMessage='Test file size in GB')] 
[ValidateSet('1','5','10','50','100','500','1000')] 
$TestFileSizeInGB = 1,

## Here, we're defining the export path to where the test file is going to reside, temporarily. 
[parameter(mandatory=$False,HelpMessage='Path to test folder')] 
[ValidateLength(3,254)] 
$TestFilepath = 'C:\Test',

## Here, we're making a declaration that 'yes, this is a test' - and which type of test are you going to want to run? 
[parameter(mandatory=$True,HelpMessage='Test mode, use Get-SmallIO for IOPS and Get-LargeIO for MB/s ')] 
[ValidateSet('Get-SmallIO','Get-LargeIO')] 
$TestMode,


## Here, you're making a choice between a fast, or standard depth of testing. 
[parameter(mandatory=$False,HelpMessage='Fast test mode or standard')] 
[ValidateSet('True','False')] 
$FastMode = 'True',


## Here, we're telling the functions to keep existing test suites to build a diff, very useful if you're running this at different times of day / levels of load to have a composite idea of what true load looks like. 
[parameter(mandatory=$False,HelpMessage='Remove existing test file')] 
[ValidateSet('True','False')] 
$RemoveTestFile='False',

## Finally, we're taking everything and outputting it into a readable format, and removing the output of the test file. 
[parameter(mandatory=$False,HelpMessage='Remove existing test file')] 
[ValidateSet('Out-GridView','Format-Table')] 
$OutputFormat='Out-GridView'
)

## In the function section, we're calling our variables and actually starting the benchmarking of the server, using native utilities. 
Function New-TestFile{
$Folder = New-Item -Path $TestFilePath -ItemType Directory -Force -ErrorAction SilentlyContinue
$TestFileAndPath = "$TestFilePath\$TestFileName"
Write-Host "Checking for $TestFileAndPath"
$FileExist = Test-Path $TestFileAndPath
if ($FileExist -eq $True)
{
    if ($RemoveTestFile -EQ 'True')
    {
        Remove-Item -Path $TestFileAndPath -Force
    }
    else
    {
        Write-Host 'File Exists, break'
        Break
    }
}
Write-Host 'Creating test file using fsutil.exe...'
& cmd.exe /c FSUTIL.EXE file createnew $TestFileAndPath ($TestFileSizeInGB*1024*1024*1024)
& cmd.exe /c FSUTIL.EXE file setvaliddata $TestFileAndPath ($TestFileSizeInGB*1024*1024*1024)
}
Function Remove-TestFile{
$TestFileAndPath = "$TestFilePath\$TestFileName"
Write-Host "Checking for $TestFileAndPath"
$FileExist = Test-Path $TestFileAndPath
if ($FileExist -eq $True)
{
    Write-Host 'File Exists, deleting'
    Remove-Item -Path $TestFileAndPath -Force -Verbose
}
}
## This is the set of operations related to the Get-SmallIO cmdlet, and you're -really- looking for IOPS, based off of **SEQUENTIAL** 8KB writes; adjust this as needed based on the usecase. This scripting was written to call SQLIO.EXE, assuming that this is being run against a MSSQL server. If this isn't a SQL server, you can safely disregard error messges. Alternatively, you can remove this if you choose to do so. 
Function Get-SmallIO{
Write-Host 'Initialize for SmallIO...'
8..64 | % {
    $KBytes = '8'
    $Type = 'random'
    $b = "-b$KBytes";
    $f = "-f$Type";
    $o = "-o $_";  
    $Result = & $RunningFromFolder\sqlio.exe $Duration -kR $f $b $o -t4 -LS -BN "$TestFilePath\$TestFileName"
    Start-Sleep -Seconds 5 -Verbose
    $iops = $Result.Split("`n")[10].Split(':')[1].Trim() 
    $mbs = $Result.Split("`n")[11].Split(':')[1].Trim() 
    $latency = $Result.Split("`n")[14].Split(':')[1].Trim()
    $SeqRnd = $Result.Split("`n")[14].Split(':')[1].Trim()
    New-object psobject -property @{
        Type = $($Type)
        SizeIOKBytes = $($KBytes)
        OutStandingIOs = $($_)
        IOPS = $($iops)
        MBSec = $($mbs)
        LatencyMS = $($latency)
        Target = $("$TestFilePath\$TestFileName")
        }
    }
}

## For the Get-LargeIO function, we want to use it in order to determine max throughput needs for whatever you're migrating. IOPS is only a part of the picture, you need to understand what kind of data transfer speeds are needed to have the full picture of the disk's performance characteristics. Default is set to **SEQUENTIAL** 512KB blocks, but this can change based on your customer/partner's workload in scope. 

Function Get-LargeIO{
$KBytes = '512'
$Type = 'sequential'
Write-Host 'Initialize for LargeIO...'
Write-Host "Reading $KBytes Bytes in $Type mode using $TestFilePath\$TestFileName as target"
1..32 | % {
    $b = "-b$KBytes";
    $f = "-f$Type";
    $o = "-o $_";  
    $Result = & $RunningFromFolder\sqlio.exe $Duration -kR $f $b $o -t1 -LS -BN "$TestFilePath\$TestFileName"
    Start-Sleep -Seconds 5 -Verbose
    $iops = $Result.Split("`n")[10].Split(':')[1].Trim() 
    $mbs = $Result.Split("`n")[11].Split(':')[1].Trim() 
    $latency = $Result.Split("`n")[14].Split(':')[1].Trim()
    $SeqRnd = $Result.Split("`n")[14].Split(':')[1].Trim()
    New-object psobject -property @{
        Type = $($Type)
        SizeIOKBytes = $($KBytes)
        OutStandingIOs = $($_)
        IOPS = $($iops)
        MBSec = $($mbs)
        LatencyMS = $($latency)
        Target = $("$TestFilePath\$TestFileName")
        }
    }
}

## Here, we're checking for whether fast mode is enabled. 
if ($FastMode -lt $True){$Duration = '-s60'}else{$Duration = '-s10'}

## Here, we're instructing the test script where to run from, and defining a location in which to find the relevant exe's
$RunningFromFolder = $MyInvocation.MyCommand.Path | Split-Path -Parent 
Write-Host “Running this from $RunningFromFolder”

#Main
. New-TestFile

## To complete this out, we're taking all the output and throwing it into a GridView to make it readable. 
switch ($OutputFormat){
    'Out-GridView' {
    . $TestMode | Select-Object MBSec,IOPS,SizeIOKBytes,LatencyMS,OutStandingIOs,Type,Target | Out-GridView
    }
    'Format-Table' {
    . $TestMode | Select-Object MBSec,IOPS,SizeIOKBytes,LatencyMS,OutStandingIOs,Type,Target | Format-Table
    }
    Default {}
}
. Remove-TestFile
