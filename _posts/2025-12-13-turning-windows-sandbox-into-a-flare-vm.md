---
layout: post
---

> **Running Untrusted Applications:** Mitigate security risks by opening untrusted applications or files, such as email attachments in WSB. Improve your safety and security by opening a sandbox with networking disabled and mapping the folder with the application or file you want to open to the sandbox in read-only mode. <br>\- [Microsoft Learn \| Windows Sandbox](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/)

When I first heard about Windows Sandbox (WSB) and saw this as a suggested use-case, I was super excited to check it out! Unfortunately, once I started digging into the technical details, I realized how limited Microsoft designed it to be... *sigh*

One of the main problems with WSB is that if you want to do *in-depth* analysis on an untrusted application, the sandbox container is so ephemeral that you would need to re-install any non-portable tools each time you start it. This can be automated using PowerShell and the [WSB CLI](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-cli), but depending on which tools you need it can be time-consuming and tedious.

{% highlight powershell linenos %}
# Example: Start WSB and initiate some installation scripts
$wsb_id_json = ((& wsb start --raw) -join "`n")
$wsb_id = ($wsb_id_json | ConvertFrom-Json).Id
wsb connect --id $wsb_id
wsb share --id $wsb_id -f $host_tool_path -s $guest_tool_path
wsb exec --id $wsb_id -c "install.cmd" -r ExistingLogin -d $guest_tool_path
{% endhighlight %}

You could have this prompt the user each time to select the tools you want and determine the right msiexec options to pass for an unattended install (does your desired tool come as an msi?), and for most installers you will likely also need internet access, which is not ideal.

I was surprised to read in Microsoft's documentation:
> Networking is enabled by default. **This can expose untrusted applications to the internal network**. To launch a Sandbox with networking disabled, use a custom .wsb file. <br>\- [Microsoft Learn \| Use and configure Windows Sandbox](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file)

But you could also probably write a script to modify the Hyper-V default switch (which WSB uses) to disable the networking after installing your tools and prevent the internal routing but now you are making changes that influence other Windows features an- *actually... what are we doing?*

The [FLARE-VM](https://github.com/mandiant/flare-vm) project already exists for analysts to easily setup and maintain tools for reverse engineering and malware analysis on a persistent image. We just needed to figure out how to make this work with WSB and make it persistent.

# Step 1: Identifying the base layer

In this [article by Check Point](https://research.checkpoint.com/2021/playing-in-the-windows-sandbox/) (2021) their researcher found the following:

> The [base layer] modification has a few simple steps:
> 1. Stop CmService, the service that creates and maintains the base layer. When the service is unloaded, it also removes the base layer mounting.
> 2. Mount the base layer (it is in the `C:\ProgramData\Microsoft\Windows\Containers\BaseImages\0949cec7-8165-4167-8c7d-67cf14eeede0\BaseLayer.vhdx` file). This can be done by double clicking, or using the diskmgmt.msc utility.
> 3. Make modifications to the base layer. In our case, we added all FLARE post-installation files.
> 4. Unmount the base layer.
> 5. Start CmService.

When I tried replicating this, I was not able to mount the VHDX ("BaseLayer.vhdx" does not exist, only disks called "sandbox.vhdx") and by even attempting to mount them, I bricked Windows Sandbox so badly that I could not restart `CmService` or turn the WSB feature off and on again using the "Windows Optional Features" GUI. Maybe I did something horribly wrong, but combined with the other inconsistencies, my current assessment is that Microsoft has since made changes to Windows Sandbox that make this technique not as simple as it once was.

This is the structure of the `C:\ProgramData\Microsoft\Windows\Containers` directory that I observed:

```bash
. C:\\ProgramData\\Microsoft\\Windows\\Containers
|
|____ BaseImages/  (EMPTY!)
|____ ContainerStorages/
|    |____ <GUID>/
|        |____ sandbox.vhdx
|        |____ sandbox.vmgs
|        |____ Bindings/
|             |____ config.json
|____ Dumps/
|    |____ <GUID>.dmp
|    |____ <GUID>.vmrs
|____ Layers/
|    |____ <GUID>/
|        |____ dotnet.bcf
|        |____ Hives/
|             |____ <symlinks to registry hives>
|        |____ Specialization/
|             |____ (this folder requires its on blog and research)
|        |____ Files/ (!!!)
|        |____ Bindings/
|             |____ config.json
|____ Snapshots/
|    |____ <GUID>/
|        |____ SnapshotSavedState.vmrs
```

I've found multiple GUID folders within `C:\ProgramData\Microsoft\Windows\Containers\Layers` but on a fresh install there will only be one. It's unclear what leads to the multiple layers being created, but logically we can use the oldest GUID folder as the "base layer".

# Step 2: Installing FLARE VM

This part is mostly simple, there are only two steps:

### Step 2a: Getting the WDAGUtilityAccount password

There is a technique demonstrated by [gerneio](https://github.com/gerneio) in their [WindowsSandboxPlayground](https://github.com/gerneio/WindowsSandboxPlayground) project to retrieve the randomly generated `WDAGUtilityAccount` password. This involves adding types from `SandboxCommon.dll` so after we copy the WSB package directory to something predictable, we can use gernio's script with [PowerShell 7](https://learn.microsoft.com/en-us/powershell/scripting/install/install-powershell-on-windows?view=powershell-7.5) and retrieve the password.

{% highlight powershell linenos %}
$wsb_home_path = "C:\ProgramData\flare-wsb"
if (-not (Test-Path $wsb_home_path)) {
    # SandboxCommon.dll and dependencies need to be in a predictable location
    $wsb_InstallLocation = (Get-AppxPackage *WindowsSandbox*).InstallLocation
    Copy-Item $wsb_InstallLocation -Destination $wsb_home_path -Recurse
}
{% endhighlight %}

{% highlight powershell linenos %}
# get_wsb_pass.ps1
using assembly "C:\ProgramData\flare-wsb\MicrosoftWindows.WindowsSandbox\SandboxCommon.dll"
$client = [SandboxCommon.Grpc.GrpcClient]::new()
$wsb_id = & wsb list
$config = $client.GetRdpClientConfigAsync($wsb_id).Result
return $config.Password
{% endhighlight %}

### Step 2b: Launching the FLARE VM installer

Now we can launch FLARE and provide the password to the installer. The FLARE installer has a GUI that you can use to pick and choose the tools you want to install, and I opted to initiate it with a `.cmd` script so that we can see the PowerShell window and keep track of the installation process.

{% highlight powershell linenos %}
$wsb_password = & $pwsh_path -NoProfile -NonInteractive \
  -File "$host_scripts_path\get_wsb_pass.ps1"
& wsb exec --id $wsb_id \
  -c "$guest_scripts_path\start_flare_install.cmd $wsb_password"
  -r ExistingLogin -d $guest_flare_path
{% endhighlight %}

{% highlight batch linenos %}
@REM start_flare_install.cmd
cmd.exe /c start "" powershell -NoExit -ExecutionPolicy Unrestricted \
  -File "C:\Users\WDAGUtilityAccount\Documents\flare-vm\install.ps1"  \
  -customLayout "C:\Users\WDAGUtilityAccount\Documents\LayoutModification.xml" \
  -customConfig "C:\Users\WDAGUtilityAccount\Documents\config.xml" -password %1 \
  -noWait -noReboots
{% endhighlight %}

# Step 3: Modifying the base layer

The config files in the `Specialization` folder looked very promising for modifying the WSB defaults, but I hit a dead end here so I won't explain what was so interesting... the real winner is the `Files` directory which has the default WSB file structure!

!["C:\ProgramData\Microsoft\Windows\Containers\Layers\GUID\Files"](/assets/2025-12-13-turning-windows-sandbox-into-a-flare-vm-1a.png)

<br>

The plan was simple:
1. Share the base layer with WSB using `wsb share`
2. Install FLARE VM on WSB
3. Copy the filesystem into the base layer

But the problem was that running `Copy-File` on many directories in the base layer (even with `wsb exec -r System`) would result in permission errors, which was likely due to "TrustedInstaller" being the owner. GPT and I wrote a quick powershell script that enumerated the mounted base layer to determine which folders we could modify.

```
C:\base_layer\EFI	 (Create:True	Modify:True	Delete:True)
C:\base_layer\ProgramData	 (Create:True	Modify:True	Delete:True)
C:\base_layer\EFI\Boot	 (Create:True	Modify:True	Delete:True)
C:\base_layer\EFI\Microsoft	 (Create:True	Modify:True	Delete:True)
C:\base_layer\EFI\Microsoft\Recovery	 (Create:True	Modify:True	Delete:True)
C:\base_layer\ProgramData\USOShared	 (Create:True	Modify:True	Delete:True)
C:\base_layer\ProgramData\Microsoft\DeviceSync	 (Create:True	Modify:True	Delete:True)
C:\base_layer\ProgramData\Microsoft\MIDI	 (Create:True	Modify:True	Delete:False)
C:\base_layer\ProgramData\Microsoft\User Account Pictures	 (Create:True	Modify:False	Delete:False)
C:\base_layer\ProgramData\Microsoft\Crypto\DSS\MachineKeys	 (Create:True	Modify:True	Delete:True)
C:\base_layer\ProgramData\Microsoft\Crypto\RSA\MachineKeys	 (Create:True	Modify:True	Delete:True)
C:\base_layer\ProgramData\Microsoft\NetFramework\BreadcrumbStore	 (Create:True	Modify:False	Delete:False)
C:\base_layer\ProgramData\Microsoft\Windows\WER\ReportArchive	 (Create:True	Modify:True	Delete:True)
C:\base_layer\ProgramData\Microsoft\Windows\WER\ReportQueue	 (Create:True	Modify:True	Delete:True)
C:\base_layer\ProgramData\Microsoft\Windows\WER\Temp	 (Create:True	Modify:True	Delete:True)
C:\base_layer\ProgramData\USOShared\Logs	 (Create:True	Modify:True	Delete:True)
C:\base_layer\ProgramData\USOShared\Logs\User	 (Create:True	Modify:True	Delete:True)
C:\base_layer\Users\Public	 (Create:True	Modify:True	Delete:True)
C:\base_layer\Users\Public\Documents	 (Create:True	Modify:True	Delete:True)
C:\base_layer\Users\Public\Downloads	 (Create:True	Modify:True	Delete:True)
C:\base_layer\Users\Public\Libraries	 (Create:True	Modify:True	Delete:True)
C:\base_layer\Users\Public\Music	 (Create:True	Modify:True	Delete:True)
C:\base_layer\Users\Public\Pictures	 (Create:True	Modify:True	Delete:True)
C:\base_layer\Users\Public\Videos	 (Create:True	Modify:True	Delete:True)
C:\base_layer\Windows\Tasks	 (Create:True	Modify:True	Delete:True)
C:\base_layer\Windows\Temp	 (Create:True	Modify:True	Delete:True)
C:\base_layer\Windows\tracing	 (Create:True	Modify:True	Delete:False)
C:\base_layer\Windows\Registration\CRMLog	 (Create:True	Modify:True	Delete:True)
C:\base_layer\Windows\System32\Tasks	 (Create:True	Modify:True	Delete:True)
C:\base_layer\Windows\System32\Com\dmp	 (Create:True	Modify:True	Delete:True)
C:\base_layer\Windows\System32\spool\PRINTERS	 (Create:True	Modify:True	Delete:True)
C:\base_layer\Windows\System32\spool\SERVERS	 (Create:True	Modify:True	Delete:True)
C:\base_layer\Windows\System32\spool\drivers\color	 (Create:True	Modify:True	Delete:True)
C:\base_layer\Windows\SysWOW64\Tasks	 (Create:True	Modify:True	Delete:True)
C:\base_layer\Windows\SysWOW64\Com\dmp	 (Create:True	Modify:True	Delete:True)
```

<br>

We can set our install locations for the FLARE VM tools in the provided `config.xml`, but we can't easily have package managers like [Chocolatey](https://chocolatey.org/) (leveraged frequently by FLARE VM) from installing to system folders like `C:\Program Files` and `C:\Program Files (x86)`. This means we can't just do a simple `Copy-File` into the base layer (except for `C:\ProgramData`!)

The `WDAGUtilityAccount` user folder is also missing from our list (the default WSB user) and tools sometimes use that directory for storing config files. There is also the problem of each tool modifying our `$PATH` and user/machine variables...

The solution is not elegant, but if we identify key installation folders we can make a copy of them to a modifiable folder in the base layer (ex. `C:\Users\Public\Documents`) and we can do the same with environment variables by using `reg export`. We just need to know which folders go where for the post-installation steps.

# Putting it all together

```
PS C:\Users\lootem\Desktop\flare-wsb> .\install.ps1
[2025-12-13 19:15:26] [~] Using CWD: C:\Users\lootem\Desktop\flare-wsb
[2025-12-13 19:15:26] [~] Install logs will be stored in: C:\ProgramData\flare-wsb\install.log
[2025-12-13 19:15:27] [~] Found pwsh at: C:\Program Files\PowerShell\7\pwsh.exe
[2025-12-13 19:15:27] [~] Starting WSB...
[2025-12-13 19:15:30] [~] Sharing flare-vm...
[2025-12-13 19:15:31] [~] Sharing bin...
[2025-12-13 19:15:31] [~] Sharing base layer with guest...
[2025-12-13 19:15:32] [~] Getting WDAGUtility password for 6cf5da30-2298-4aff-bbbd-4467f7cfd3f4...
[2025-12-13 19:15:34] [+] WDAGUtilityAccount:b172a79f-661f-4a96-80cb-38c56cf43ece
[2025-12-13 19:15:34] [~] Waiting a few seconds before starting Flare installer...
[2025-12-13 19:15:44] [~] Starting Flare installer...
Process exited with code: 0
[!] Press any key when Flare is finished installing:
```
<center><strong>1. Starting "install.ps1"</strong></center>
<br>
![FLARE VM Installer GUI](/assets/2025-12-13-turning-windows-sandbox-into-a-flare-vm-1b.png)
<center><strong>2. FLARE VM Installer GUI in sandbox</strong></center>
<br>
![Default install location is base layer](/assets/2025-12-13-turning-windows-sandbox-into-a-flare-vm-1c.png)
<center><strong>3. Default install location is base layer</strong></center>
<br>
![Select your tools (ex. Ghidra)](/assets/2025-12-13-turning-windows-sandbox-into-a-flare-vm-1d.png)
<center><strong>4. Select your tools (ex. Ghidra)</strong></center>
<br>
![Install complete](/assets/2025-12-13-turning-windows-sandbox-into-a-flare-vm-1e.png)
<center><strong>5. Install complete</strong></center>
<br>
```
[!] Press any key when Flare is finished installing:
[2025-12-13 19:28:04] [~] Saving to base layer...
[2025-12-13 19:28:04] [~] Running user script...
Process exited with code: 0
[2025-12-13 19:28:08] [~] Running system script...
Process exited with code: 0
[2025-12-13 19:29:13] [~] Stopping WSB...
[2025-12-13 19:29:14] [+] Flare installed to base layer! You are all set!
[2025-12-13 19:29:14] [+] Start your new Flare WSB with: flare-wsb.bat
```
<center><strong>6. "install.ps1" continued</strong></center>
<br>
```
[!] This script is for starting WSB after installing Flare to the base image. Use 'install.ps1' to setup.
[~] Attach networking? (Y/N) (Default: No):
[~] Make shared folder writeable by sandbox? (Y/N) (Default: No):
[~] Starting WSB (Networking: No)...
[~] Adding script directory...
[~] Adding shared folder to desktop...
[+] Shared folder: C:\Users\lootem\Desktop\flare-wsb\bin\scripts
[~] Starting system script...
Process exited with code: 0
[~] Waiting a few seconds for login...
[~] Starting post installation script...
Process exited with code: 0
[+] Done!
[!] Press any key to stop WSB or exit this script to stop it on your own time:
```
<center><strong>7. Starting "flare-wsb.bat"</strong></center>
<br>
![FLARE VM in Windows Sandbox](/assets/2025-12-13-turning-windows-sandbox-into-a-flare-vm-1f.png)
<center><strong>8. FLARE VM in Windows Sandbox!</strong></center>

### Code: [http://github.com/lootem/flare-wsb](http://github.com/lootem/flare-wsb)

### Credits and Acknowledgements
- Mandiant/Google and the maintainers of [FLARE-VM](https://github.com/mandiant/flare-vm).
- Alex Ilgayev at Check Point with their [Windows Sandbox research](https://research.checkpoint.com/2021/playing-in-the-windows-sandbox/) and the idea for this project.
- [gerneio](https://github.com/gerneio) and their [WindowsSandboxPlayground](https://github.com/gerneio/WindowsSandboxPlayground) project for the WDAGUtilityAccount password retrieval technique and their collection of Windows Sandbox research.

Thanks for reading!
<br>
\- lootem