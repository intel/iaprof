#include <utils/demangle.h>

#include <cstring>
#include <llvm/Demangle/Demangle.h>

static char *_demangle(const char *mangled) {
        std::string demangled;

        demangled = llvm::demangle(mangled);
        if (demangled == mangled) {
                return NULL;
        }

        return strdup(demangled.c_str());
}

extern "C" char *demangle(const char *mangled) {
        return _demangle(mangled);
}
