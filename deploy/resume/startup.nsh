@echo -off
# startup.nsh — EFI partition auto-run script
# maintest.nsh is on the FAT32 EFI partition (written by pytest via sudo tee).
# We search fs0:-fs9: because the UEFI shell current dir may not be EFI root.
#
# Installed to /boot/efi/startup.nsh by deploy/setup/setup_sut.sh (step 2).
# Manual install:  sudo cp deploy/resume/startup.nsh /boot/efi/startup.nsh
# Disable after testing:  sudo rm /boot/efi/startup.nsh
#   (otherwise the UEFI shell looks for maintest.nsh on every boot)

for %d run (0 9)
    if exist fs%d:\maintest.nsh then
        echo Found maintest.nsh on fs%d:
        set EFIDRV fs%d:
        fs%d:
        maintest.nsh
        goto done
    endif
endfor

echo No maintest.nsh found on any filesystem (fs0:-fs9:)
echo Continuing normal boot...

:done
