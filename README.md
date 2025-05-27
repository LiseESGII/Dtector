# Dtector

Projet pédagogique en assembleur x86-64 Linux, conçu pour détecter rapidement des patterns malveillants dans du shellcode fourni par l'utilisateur (au format hexadécimal).

Fonctionnalités :

    Affichage d'un banner et d'un prompt interractif
    Lecture et exécution d'un shellcode héxadécimal en binaire
    Détection de patterns malveillants (NOP sled 0x90 0x90 0x90) (Syscall suspect 0x0f 0x05)
    Comptage et affichage des menaces détectées
    Message de sécurité si aucune menace trouvée

1. Sauvegarder le code

nano detector.s
2. Assembler le fichier

as --64 detector.s -o detector.o
3. Linker pour créer l'exécutable

ld detector.o -o detector
4. Rendre exécutable (si nécessaire)
chmod +x detector
