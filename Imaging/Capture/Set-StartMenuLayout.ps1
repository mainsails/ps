# Customise Windows Start Menu for OS Deployment
# Output of 'Export-StartLayout -Path C:\LayoutModification.xml' is copied to '$env:SystemDrive\users\default\appdata\local\Microsoft\Windows\Shell'
# Windows 10

# The powershell cmdlet above exports the current Start Menu ("metro") layout to xml
# Copying the exported xml to the stated folder recreates the same exported Start Menu for all new users


# Set Variables
$SourceFile        = "$TSEnv:DEPLOYROOT\Branding\LayoutModification.xml"
$DestinationFolder = "$env:SystemDrive\users\default\appdata\local\Microsoft\Windows\Shell"

# Copy Start Menu Export
Copy-Item -Path $SourceFile -Destination $DestinationFolder