QT += core
QT -= gui

CONFIG += c++11

TARGET = my_d2_mingw
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

SOURCES += main.cpp \
    bearopgadgetfinder.cpp \
    cpu.cpp \
    elf.cpp \
    elf_struct.cpp \
    executable_format.cpp \
    gadget.cpp \
    instruction.cpp \
    macho.cpp \
    pe.cpp \
    program.cpp \
    raw.cpp \
    rpexception.cpp \
    section.cpp \
    toolbox.cpp \
    x64.cpp \
    x86.cpp

# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

HEADERS += \
    inc/bearopgadgetfinder.hpp \
    inc/coloshell.hpp \
    inc/cpu.hpp \
    inc/elf.hpp \
    inc/elf_struct.hpp \
    inc/executable_format.hpp \
    inc/gadget.hpp \
    inc/instruction.hpp \
    inc/macho.hpp \
    inc/macho_struct.hpp \
    inc/main.hpp \
    inc/pe.hpp \
    inc/pe_struct.hpp \
    inc/platform.h \
    inc/program.hpp \
    inc/raw.hpp \
    inc/rpexception.hpp \
    inc/safeint.hpp \
    inc/section.hpp \
    inc/toolbox.hpp \
    inc/x64.hpp \
    inc/x86.hpp \
    include/beaengine/basic_types.h \
    include/beaengine/beaengine.h \
    include/beaengine/export.h \
    include/beaengine/macros.h

INCLUDEPATH += $$PWD/include \
               $$PWD/inc
DEPENDPATH += $$PWD/include

LIBS += $$PWD/lib/libBeaEngine_s_d_l.a
