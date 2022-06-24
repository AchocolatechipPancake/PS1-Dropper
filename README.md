# Elevated PS1 execution via EXE
Creates a ps1 file then executes via UAC bypass function

## Replace the string contents with your script (Line 210)
```
	string powershell = R"(
$filenames = Get-ChildItem \\Shared\TestFolder\*.txt | select -expand fullname
$filenames -match "testfile1.txt"
If ($filenames -eq 'False') {
	 New -Item -Path '\\Shared\TestFolder\testfile1.txt' -ItemType File
}
else {exit}
)";
```

