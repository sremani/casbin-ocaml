# Casbin OCaml: PitBoss and PitCrew

The human has authorized a PitBoss-led team of PitCrew subagents. PitBoss owns scope, interfaces, integration, and final verification. PitCrew members own assigned files and report evidence and blockers.

Operate proactively from PITBOARD.md: PitBoss keeps a prioritized ticket backlog, dispatches ready tickets, resolves routine decisions and dependencies, reviews crew evidence, integrates changes, runs gates, and commits verified milestones. A milestone completion is a checkpoint for selecting the next ready wave, not a reason to ask the user to repeat authorization. Ask only when a material user choice or external permission is truly missing. Update ticket owner/status/evidence as work progresses; never mark unfinished work done.

All project work stays in this directory. Avoid unrelated workspace changes. Do not change another crew member's files without coordinating with PitBoss. Do not commit the surrounding workspace.

The first few milestones use local Git commits in this project's isolated repository. PitBoss owns commits: each completed, verified milestone gets a local commit. PitCrew report completion and verification evidence; do not commit independently unless PitBoss explicitly assigns that work. The intended local branch is codex/casbin-ocaml. Commit only this project repository, never the surrounding workspace.

The human authorized GitHub publication on 2026-10-01. This project's repository is https://github.com/sremani/casbin-ocaml. PitBoss owns reviewed publication and Git integration; preserve the verified local milestone history. Public package registry publication is separate scope.

First milestone: an idiomatic OCaml library and CLI implementing a declared string-valued ACL/basic RBAC subset of pinned Go Casbin behavior. Unsupported model/matcher features must produce errors, never silently authorize. Use the OCaml 5.5 series (>= 5.5 and < 5.6) and Dune 3.1 or later with the standard library; do not add dependencies without coordinating.

The compiler standard applies to the active PATH toolchain. Run scripts/check_toolchain.sh before builds or verification; it requires both ocamlc and ocamlopt to report a 5.5.* version. scripts/verify.sh runs this guard before any build or network operation. Keep toolchain selection local to the project/session; do not install, remove, or change global toolchains for this project.

The reference source is upstream/casbin at commit 524f3f2dc9baef696d748db491d49b3055d359d1. Do not modify it. Preserve LICENSE and NOTICE when copying fixtures. Record fixture provenance. Tests should target semantic boundaries and compare supported behavior to the Go oracle.

Public signatures written by PitBoss are the coordination contract. Report needed changes before altering them. Build/test runs may share Dune's build directory; coordinate if contention occurs.
