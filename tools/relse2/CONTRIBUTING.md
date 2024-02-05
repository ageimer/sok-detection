# Develop in BINSEC

If you are not familiar with `git`, consider reading some tutorials
(e.g. [gitlab on the command line](https://docs.gitlab.com/ee/gitlab-basics/start-using-git.html)).

Interns, PhD students, postdoctoral fellows and tenured researchers of 
[binary group](https://git.frama-c.com/binary) can create new branches
and experiment with the code on their own.

To create a new branch, simply run the following.
```console
$ git switch --create the-name-of-the-branch
```
*We advise you to push you local changes as often as possible.* 

When you develop on long-lived branches, you can keep up with the fixes that are pushed to devel by merging:
```console
$ git merge devel
```
If there are conflicts, `git status` will tell you what to do.

## Recommended development setup

If you just checked out the repository, run the following to enable
[pre-commit](utils/pre-commit) hook and avoid bad surprises.
```console
$ git config --local include.path ../.gitconfig
```

opam
-
For [opam](https://opam.ocaml.org/) users, run the following to create
a clean development environment.
```console
$ OCAML_COMPILER=4.08.1 make switch
```
It will install [merlin](https://github.com/ocaml/merlin) and
[ocamlformat](https://github.com/ocaml-ppx/ocamlformat) to ease the
ocaml development.

nix
-
After installing [nix](https://nixos.org/manual/nix/stable/installation/installing-binary.html?highlight=install%20daemon#multi-user-installation), run
```console
$ nix-shell
```
at the root of the repo. The shell that spawns contains all required dependencies: you can run your favorite IDE inside it.
For a more comfortable setup, see [lorri](https://github.com/nix-community/lorri/)

emacs
-
[opam setup](#opam) also installs
[user-setup](https://github.com/ocaml-opam/opam-user-setup).  
Everything should work out of the box.

For working with git, the use of [magit](https://magit.vc/), a well-known UI to git integrated to emacs, is recommended.

Add the following lines to automatically format your code when saving.
```lisp
(use-package ocamlformat
  :load-path
  (lambda ()
    (concat
         ;; Never use "/" or "\" since this is not portable (opam-user-setup does this though)
         ;; Always use file-name-as-directory since this will append the correct separator if needed
         ;; (or use a package that does it well like https://github.com/rejeep/f.el)
         ;; This is the verbose and not package depending version:
         (file-name-as-directory
          ;; Couldn't find an option to remove the newline so a substring is needed
          (substring (shell-command-to-string "opam config var share --safe") 0 -1))
         (file-name-as-directory "emacs")
         (file-name-as-directory "site-lisp")))
  :custom
  (ocamlformat-command
   (concat
    (file-name-as-directory
     (substring (shell-command-to-string "opam config var bin --safe") 0 -1))
    "ocamlformat"))
  :hook (before-save . ocamlformat-before-save)
  )
```

vim
-
*Feel free to complete.*

VScode
-
*Feel free to complete.*

# Contributing to BINSEC

**BINSEC**'s common development happens in the protected `devel` branch.  
Once your work is ready, you should consider
[opening a merge request](https://git.frama-c.com/binary/binsec/-/merge_requests/new)
to share your contribution with others.

There are 4 main kinds of contribution:
documentation, fix, refactoring and feature.

## Documentation

Any documentation improvement, whether it be user
(tutorial, reference manual, etc.) or developer
(installation, interface signature, etc.)
oriented, is much appreciated.  
*Only requirement is it should be in english.*

## Fix

If you find a bug in **BINSEC**, you should
[open an issue](https://git.frama-c.com/binary/binsec/-/issues/new) first.  
You can assign any non assigned issue to yourself if you know how to fix
the bug.

To implement the fix, start from the current version of `devel`.
```console
$ git fetch
$ git checkout devel
$ git pull
```
Then create a new branch (usually prefixed by "fix").
```console
$ git checkout -b fix/what-it-fixes
```
Then start implementing the fix.

If the fix already exists in one of your branch, consider cherry-picking the
commit(s).  
Run the following to find the hash of your commit(s).
```console
$ git log
```
Then import them with the following.
```console
$ git cherry-pick hash-of-the-commit
```
Finally, push the new branch upstream.
```console
$ git push --set-upstream origin fix/what-it-fixes
```
In the merge request description, do not forget to reference the patched
issue(s).  
For instance, the merge request !203 closed the issue #179.
```text
Closes #179.
```

## Refactoring

*Refactoring requires a good knowledge of **BINSEC** code, good `ocaml` skills
and may take a lot of time.*

So, to a certain extend, changes improving the quality of the code base
are welcomed but, keep in mind your primary objective.  
Also, you must consider opening a discussion before doing any changes that will
strongly impact other developers (e.g. updating a module interface).

The same as for [fixes](#fix), your development should start from the
current version of `devel` and it is better to prefix the branch name with
`refactor/`.

## Feature

*Coming soon.*
