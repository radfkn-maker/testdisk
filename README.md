Improved file recovery

To control all aspects of the recovery (file content check, file size control, footer detection...), the best way to add a signature, if you are developer, is to modify PhotoRec itself.
Objective

Your task is to modify the testdisk (specifically the PhotoRec component) codebase in this repository to support advanced carving of cryptocurrency wallets and private keys.

You will create dedicated, modular C files for each target data type. You must strictly use the following existing files in the repository as structural and logical templates:

    src/file_bac.c

    src/file_mp3.c

    src/file_wallet.c

These templates are located at: https://github.com/radfkn-maker/testdisk/tree/main/src
Handling File Sizes (Crucial Requirement)

PhotoRec relies heavily on accurate file size calculations to prevent carving enormous, useless files or cutting data off prematurely. When examining the template files, pay close attention to how they handle file limits. For instance, in file_bac.c, you will see variables like file_recovery_new->min_filesize and file_recovery_new->calculated_file_size being explicitly defined based on the parsed block size.

You must apply highly relevant sizing logic for the new crypto signatures:

    Known/Fixed Sizes: If a private key or backup is always a specific byte length, calculate and set calculated_file_size to that exact number.

    Header-Defined Sizes: If the file format dictates its own size in the header, parse it and set calculated_file_size accordingly.

    Indeterminate Sizes: If the exact size is unknown (like some JSON wallets), set a reasonable maximum fallback size to stop the carving process and prevent run-away data extraction.

Required Modules to Implement

Based on the provided templates, implement the following new modules in the src/ directory:

    file_dat.c (Bitcoin Core / Berkeley DB wallets)

    file_multibit.c (MultiBit Classic / HD wallets)

    file_electrum.c (Electrum JSON / AES-encrypted wallets)

    file_prvkey.c (Raw private keys, PEM, and encrypted backups)

Integration Steps

    Analyze Templates: Study file_bac.c, file_mp3.c, and file_wallet.c at the provided URL to understand the exact C struct definitions PhotoRec expects.

    Write Modules: Draft the four new .c files ensuring accurate header, footer, and file size boundary logic.

    Update Build System: Add the new files to src/Makefile.am (and CMakeLists.txt / meson.build if applicable).

    Register Signatures: Update the main signature registration array to initialize the new formats.

Output Requirements

Execute the creation of these files and the modification of the build system. Output the changes as standard Git commits or provide the exact file contents so they can be reviewed and applied.
