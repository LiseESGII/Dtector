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

    # Patterns à détecter
    # Pattern NOP sled (succession de 0x90)
    nop_pattern:    .byte 0x90, 0x90, 0x90
    nop_msg:        .ascii "NOP sled\0"

    # Pattern syscall (0x0f 0x05)
    syscall_pattern: .byte 0x0f, 0x05
    syscall_msg:    .ascii "Syscall suspect\0"

    # Buffers et compteurs
    input_buf:      .space 256    # Buffer d'entrée
    binary_buf:     .space 128    # Buffer binaire
    threat_count:   .quad 0       # Compteur de menaces

.section .text
.global _start

_start:
    # Affichage et lecture
    call show_banner
    call get_input

    # Conversion et analyse
    call hex_to_bin
    call scan_threats

    # Résultats
    call show_results

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

# Convertir hex vers binaire (version simplifiée)
hex_to_bin:
    mov $input_buf, %rsi    # source
    mov $binary_buf, %rdi   # destination
    xor %rcx, %rcx          # compteur bytes

hex_loop:
    lodsb                   # charger caractère
    cmp $0, %al            # fin de chaîne?
    je hex_done

    # Ignorer espaces
    cmp $32, %al           # espace
    je hex_loop

    # Convertir premier caractère
    call char_to_hex
    shl $4, %al            # décaler 4 bits
    mov %al, %bl           # sauvegarder

    # Deuxième caractère
    lodsb
    cmp $0, %al
    je hex_done
    call char_to_hex
    or %bl, %al            # combiner

    # Stocker byte
    stosb
    inc %rcx
    jmp hex_loop

hex_done:
    mov %rcx, %r15         # sauver nombre de bytes
    ret

#  Convertir caractère vers valeur hex
char_to_hex:
    # 0-9
    cmp $48, %al           # '0'
    jl char_done
    cmp $57, %al           # '9'
    jle sub_zero

    # A-F
    cmp $65, %al           # 'A'
    jl char_done
    cmp $70, %al           # 'F'
    jle sub_a

    # a-f
    cmp $97, %al           # 'a'
    jl char_done
    cmp $102, %al          # 'f'
    jle sub_a_lower

char_done:
    ret

sub_zero:
    sub $48, %al           # '0' = 48
    ret

sub_a:
    sub $55, %al           # 'A' = 65, -55 = 10
    ret

sub_a_lower:
    sub $87, %al           # 'a' = 97, -87 = 10
    ret

# Scanner les menaces
scan_threats:
    mov $0, threat_count   # reset compteur

    # Chercher NOP sled
    call find_nop_sled

    # Chercher syscalls
    call find_syscalls

    ret

# Détecter NOP sled
find_nop_sled:
    mov $binary_buf, %rsi  # début buffer
    mov %r15, %rcx         # nombre de bytes
    sub $2, %rcx           # ajuster pour pattern de 3

nop_scan:
    cmp $0, %rcx
    je nop_done

    # Vérifier 3 bytes NOP consécutifs
    movb (%rsi), %al
    cmp $0x90, %al
    jne nop_next

    movb 1(%rsi), %al
    cmp $0x90, %al
    jne nop_next

    movb 2(%rsi), %al
    cmp $0x90, %al
    jne nop_next

    # NOP trouvé!
    incq threat_count
    call report_nop

nop_next:
    inc %rsi
    dec %rcx
    jmp nop_scan

nop_done:
    ret

# Détecter syscalls
find_syscalls:
    mov $binary_buf, %rsi
    mov %r15, %rcx
    dec %rcx               # ajuster pour pattern de 2

syscall_scan:
    cmp $0, %rcx
    je syscall_done

    # Vérifier pattern 0x0f 0x05
    movb (%rsi), %al
    cmp $0x0f, %al
    jne syscall_next

    movb 1(%rsi), %al
    cmp $0x05, %al
    jne syscall_next

    # Syscall trouvé!
    incq threat_count
    call report_syscall

syscall_next:
    inc %rsi
    dec %rcx
    jmp syscall_scan

syscall_done:
    ret

# Signaler NOP sled
report_nop:
    mov $1, %rax
    mov $1, %rdi
    mov $danger_msg, %rsi
    mov $25, %rdx
    syscall

    mov $1, %rax
    mov $1, %rdi
    mov $nop_msg, %rsi
    mov $8, %rdx
    syscall

    mov $1, %rax
    mov $1, %rdi
    mov $newline, %rsi
    mov $1, %rdx
    syscall
    ret
