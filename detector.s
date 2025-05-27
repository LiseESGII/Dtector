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

.section .text
.global _start

_start:
    # Affichage et lecture
    call show_banner
    call get_input

# Afficher le banner
show_banner:
    mov $1, %rax        # write syscall
    mov $1, %rdi        # stdout
    mov $banner, %rsi   # message
    mov $31, %rdx       # taille
    syscall
    ret
