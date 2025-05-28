; Analyseur de Shellcode
; Architecture: x86-64 Linux
; Objectif: Détecter des patterns malveillants dans du shellcode

section .data

banner:        db "=== DETECTEUR DE SHELLCODE ===",10,0
prompt:        db "Shellcode (hex): ",0
safe_msg:      db "[OK] Code semble sain",10,0
danger_msg:    db "[ALERTE] Menace detectee: ",0
newline:       db 10,0

nop_pattern:   db 0x90, 0x90, 0x90
nop_msg:       db "NOP sled",0

syscall_pattern: db 0x0f, 0x05
syscall_msg:   db "Syscall suspect",0

input_buf:     times 256 db 0
binary_buf:    times 128 db 0
threat_count:  dq 0

section .bss
; (rien ici, tout est déjà alloué dans .data)

section .text
global _start

_start:
    ; Affichage et lecture
    call show_banner
    call get_input

    ; Conversion et analyse
    call hex_to_bin
    call scan_threats

    ; Résultats
    call show_results

    ; Sortie programme
    mov rax, 60
    mov rdi, 0
    syscall

; Afficher le banner
show_banner:
    mov rax, 1          ; write syscall
    mov rdi, 1          ; stdout
    mov rsi, banner
    mov rdx, 31
    syscall
    ret

; Lire l'entrée utilisateur
get_input:
    ; Afficher prompt
    mov rax, 1
    mov rdi, 1
    mov rsi, prompt
    mov rdx, 17
    syscall

    ; Lire depuis stdin
    mov rax, 0          ; read syscall
    mov rdi, 0          ; stdin
    mov rsi, input_buf
    mov rdx, 255
    syscall

    ; Enlever le \n final
    mov rdi, input_buf
    call remove_newline
    ret

; Convertir hex vers binaire (version simplifiée)
hex_to_bin:
    mov rsi, input_buf      ; source
    mov rdi, binary_buf     ; destination
    xor rcx, rcx            ; compteur bytes

hex_loop:
    lodsb                   ; charger caractère (rsi->al, rsi++)
    cmp al, 0
    je hex_done

    ; Ignorer espaces
    cmp al, 32
    je hex_loop

    ; Convertir premier caractère
    call char_to_hex
    shl al, 4
    mov bl, al              ; sauvegarder

    ; Deuxième caractère
    lodsb
    cmp al, 0
    je hex_done
    call char_to_hex
    or al, bl

    ; Stocker byte
    stosb                   ; al -> [rdi], rdi++
    inc rcx
    jmp hex_loop

hex_done:
    mov r15, rcx            ; sauver nombre de bytes
    ret

; Convertir caractère vers valeur hex
char_to_hex:
    ; 0-9
    cmp al, '0'
    jl char_done
    cmp al, '9'
    jle sub_zero
    ; A-F
    cmp al, 'A'
    jl char_done
    cmp al, 'F'
    jle sub_a
    ; a-f
    cmp al, 'a'
    jl char_done
    cmp al, 'f'
    jle sub_a_lower
char_done:
    ret
sub_zero:
    sub al, '0'
    ret
sub_a:
    sub al, 55      ; 'A' = 65, -55 = 10
    ret
sub_a_lower:
    sub al, 87      ; 'a' = 97, -87 = 10
    ret

; Scanner les menaces
scan_threats:
    mov qword [threat_count], 0     ; reset compteur
    call find_nop_sled
    call find_syscalls
    ret

; Détecter NOP sled
find_nop_sled:
    mov rsi, binary_buf
    mov rcx, r15
    sub rcx, 2
nop_scan:
    cmp rcx, 0
    je nop_done
    mov al, [rsi]
    cmp al, 0x90
    jne nop_next
    mov al, [rsi+1]
    cmp al, 0x90
    jne nop_next
    mov al, [rsi+2]
    cmp al, 0x90
    jne nop_next
    ; NOP trouvé !
    inc qword [threat_count]
    call report_nop
nop_next:
    inc rsi
    dec rcx
    jmp nop_scan
nop_done:
    ret

; Détecter syscalls
find_syscalls:
    mov rsi, binary_buf
    mov rcx, r15
    dec rcx
syscall_scan:
    cmp rcx, 0
    je syscall_done
    mov al, [rsi]
    cmp al, 0x0f
    jne syscall_next
    mov al, [rsi+1]
    cmp al, 0x05
    jne syscall_next
    ; Syscall trouvé !
    inc qword [threat_count]
    call report_syscall
syscall_next:
    inc rsi
    dec rcx
    jmp syscall_scan
syscall_done:
    ret

; Signaler NOP sled
report_nop:
    mov rax, 1
    mov rdi, 1
    mov rsi, danger_msg
    mov rdx, 25
    syscall

    mov rax, 1
    mov rdi, 1
    mov rsi, nop_msg
    mov rdx, 8
    syscall

    mov rax, 1
    mov rdi, 1
    mov rsi, newline
    mov rdx, 1
    syscall
    ret

; Signaler syscall
report_syscall:
    mov rax, 1
    mov rdi, 1
    mov rsi, danger_msg
    mov rdx, 25
    syscall

    mov rax, 1
    mov rdi, 1
    mov rsi, syscall_msg
    mov rdx, 15
    syscall

    mov rax, 1
    mov rdi, 1
    mov rsi, newline
    mov rdx, 1
    syscall
    ret

; Afficher résultats finaux
show_results:
    mov rax, [threat_count]
    cmp rax, 0
    jne threats_found
    ; Aucune menace
    mov rax, 1
    mov rdi, 1
    mov rsi, safe_msg
    mov rdx, 19
    syscall
    ret
threats_found:
    mov rax, 1
    mov rdi, 1
    mov rsi, newline
    mov rdx, 1
    syscall
    ret

; Enlever newline
remove_newline:
    mov al, [rdi]
    cmp al, 0
    je remove_done
    cmp al, 10
    je replace_null
    inc rdi
    jmp remove_newline
replace_null:
    mov byte [rdi], 0
remove_done:
    ret
