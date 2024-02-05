To get a shell to build binsec: at the root of the repository run `nix-shell`

To check that binsec builds: `nix-build nix/pkgs.nix -A binsec`

To obtain the appimage: `nix-build nix/pkgs.nix -A binsec_appimage`. The appimage is in 
the folder `result`.

To update a dependency: `niv update unisim`

To replace a dependency by a local checkout:
```
niv drop libase
niv add local --name libase --path /home/symphorien/src/libase
```
To revert:
```
niv drop libase
niv add git --name libase git@git.frama-c.com:lemerre/libase.git
```



