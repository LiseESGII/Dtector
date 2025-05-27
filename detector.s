# Analyseur de Shellcode
# Architecture: x86-64 Linux
# Objectif: Détecter des patterns malveillants dans du shellcode

.section .data
    # Messages de base
    banner:         .ascii "=== DETECTEUR DE SHELLCODE ===\n\0"
    prompt:         .ascii "Shellcode (hex): \0"
    safe_msg:       .ascii "[OK] Code semble sain\n\0"
    danger_msg:     .ascii "[ALERTE] Menace detectee: \0"
    newline:        .ascii "\n\0"
