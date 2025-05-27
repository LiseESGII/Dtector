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

#  Lire l'entrée utilisateur
get_input:
    # Afficher prompt
    mov $1, %rax
    mov $1, %rdi
    mov $prompt, %rsi
    mov $17, %rdx
    syscall
    
    # Lire depuis stdin
    mov $0, %rax        # read syscall
    mov $0, %rdi        # stdin
    mov $input_buf, %rsi # buffer
    mov $255, %rdx      # taille max
    syscall
    
    # Enlever le \n final
    mov $input_buf, %rdi
    call remove_newline
    ret
