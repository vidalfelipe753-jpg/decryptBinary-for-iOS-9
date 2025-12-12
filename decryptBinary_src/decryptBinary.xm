#import <Foundation/Foundation.h>
#import <mach-o/loader.h>
#import <mach-o/dyld.h>
#import <sys/stat.h>
#import <string.h>
#import <fcntl.h>
#import <errno.h>
#import <dlfcn.h>

static NSString* getCurrentBundleID() {
    NSBundle *mainBundle = [NSBundle mainBundle];
    NSString *bundleID = [mainBundle bundleIdentifier];
    return bundleID;
}

static NSString* getExecutableName() {
    NSBundle *mainBundle = [NSBundle mainBundle];
    // Use CFBundleExecutable for consistent naming
    NSString *execName = [mainBundle objectForInfoDictionaryKey:@"CFBundleExecutable"];
    return execName;
}

static NSString* getOutputPath() {
    // Get Documents directory (more accessible)
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    if (paths.count > 0) {
        NSString *documentsPath = paths[0];
        NSLog(@"[DecryptBinary] Using Documents path: %@", documentsPath);
        return [NSString stringWithFormat:@"%@/%@.decrypted", documentsPath, getExecutableName()];
    }

    return nil;
}

static void dumpBinary(const struct mach_header *targetHeader, const char *targetPath) {
    if (!targetHeader || !targetPath) {
        NSLog(@"[DecryptBinary] Invalid parameters");
        return;
    }

    NSString *outputPath = getOutputPath();
    if (outputPath == nil) {
        NSLog(@"[DecryptBinary] Cannot determine output path");
        return;
    }
    NSLog(@"[DecryptBinary] Source path: %s", targetPath);
    NSLog(@"[DecryptBinary] Output path: %@", outputPath);

    // Open files
    int oldFile = open(targetPath, O_RDONLY);
    if (oldFile < 0) {
        NSLog(@"[DecryptBinary] Cannot open source file: %s (errno: %d - %s)", targetPath, errno, strerror(errno));
        return;
    }

    int newFile = open([outputPath UTF8String], O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (newFile < 0) {
        NSLog(@"[DecryptBinary] Cannot open output file: %@ (errno: %d - %s)", outputPath, errno, strerror(errno));
        close(oldFile);
        return;
    }

    // Get file size
    struct stat st;
    if (fstat(oldFile, &st) < 0) {
        NSLog(@"[DecryptBinary] Cannot get file size");
        close(oldFile);
        close(newFile);
        return;
    }

    // Copy entire file
    char buffer[4096];
    ssize_t bytesRead;
    off_t totalBytes = 0;
    while ((bytesRead = read(oldFile, buffer, sizeof(buffer))) > 0) {
        write(newFile, buffer, bytesRead);
        totalBytes += bytesRead;
    }

    // Parse Mach-O header
    BOOL is64bit = NO;
    uint32_t magic = *(uint32_t*)targetHeader;
    uint32_t headerSize = 0;

    if (magic == MH_MAGIC || magic == MH_CIGAM) {
        is64bit = NO;
        headerSize = sizeof(struct mach_header);
    } else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        is64bit = YES;
        headerSize = sizeof(struct mach_header_64);
    } else {
        NSLog(@"[DecryptBinary] Unknown magic: 0x%x", magic);
        close(oldFile);
        close(newFile);
        return;
    }

    uint32_t ncmds = 0;
    if (is64bit) {
        ncmds = ((struct mach_header_64*)targetHeader)->ncmds;
    } else {
        ncmds = targetHeader->ncmds;
    }

    // Find encryption info
    uint32_t offset = headerSize;
    uint32_t cryptoffset = 0;
    uint32_t cryptsize = 0;
    uint32_t cryptoffset_offset = 0;

    for (uint32_t i = 0; i < ncmds; i++) {
        struct load_command *lc = (struct load_command*)((uint8_t*)targetHeader + offset);

        if (lc->cmd == LC_ENCRYPTION_INFO || lc->cmd == LC_ENCRYPTION_INFO_64) {
            struct encryption_info_command *eic = (struct encryption_info_command*)lc;
            cryptoffset = eic->cryptoff;
            cryptsize = eic->cryptsize;
            cryptoffset_offset = offset + 16; // offset to cryptid field
            break;
        }

        offset += lc->cmdsize;
    }

    // Decrypt
    if (cryptoffset_offset > 0 && cryptsize > 0) {
        NSLog(@"[DecryptBinary] Found encrypted segment at offset: 0x%x, size: 0x%x", cryptoffset, cryptsize);

        // Clear cryptid in the new file
        uint32_t zero = 0;
        lseek(newFile, cryptoffset_offset, SEEK_SET);
        write(newFile, &zero, sizeof(zero));

        // Overwrite encrypted section with decrypted data from memory
        lseek(newFile, cryptoffset, SEEK_SET);
        ssize_t written = write(newFile, (uint8_t*)targetHeader + cryptoffset, cryptsize);

        if (written == cryptsize) {
            NSLog(@"[DecryptBinary] Successfully decrypted %d bytes", cryptsize);
        } else {
            NSLog(@"[DecryptBinary] Warning: only wrote %zd of %d bytes", written, cryptsize);
        }
    } else {
        NSLog(@"[DecryptBinary] No encryption found or already decrypted");
    }

    fchmod(newFile, 0644);

    NSLog(@"[DecryptBinary] Saved to: %@", outputPath);

    close(oldFile);
    close(newFile);
}

static void onImageLoaded(const struct mach_header *header, intptr_t slide) {
    static BOOL dumped = NO;
    if (dumped) return;

    Dl_info imageInfo;
    if (dladdr(header, &imageInfo) == 0) return;
    
    const char *imagePath = imageInfo.dli_fname;
    if (!imagePath) return;

    NSString *mainExecPath = [[NSBundle mainBundle] executablePath];
    if (!mainExecPath) return;

    if (strcmp(imagePath, [mainExecPath UTF8String]) == 0) {
        dumped = YES;
        NSLog(@"[DecryptBinary] Main binary loaded.");
        NSLog(@"[DecryptBinary] ======= STARTING DUMP =======");
        dumpBinary(header, imagePath);
        NSLog(@"[DecryptBinary] ======= DUMP COMPLETE =======");
    }
}

%ctor {
    NSString *bundleID = getCurrentBundleID();
    NSString *execName = getExecutableName();

    NSLog(@"[DecryptBinary] ======= TWEAK LOADED =======");
    NSLog(@"[DecryptBinary] PID: %d", getpid());
    NSLog(@"[DecryptBinary] Executable Name: %@", execName);
    NSLog(@"[DecryptBinary] Bundle ID: %@", bundleID);

    _dyld_register_func_for_add_image(onImageLoaded);
}
