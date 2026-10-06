#-------------------------------------------------
#
# Project created by QtCreator 2026-10-02T16:00:35
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = NPC
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0


# 把「本 .pro 文件所在目录」下的 samples 目录，变成一个"编译期常量"递给代码
# $$PWD = 本 .pro 文件所在的文件夹
# \\\" 是转义：编译器最终看到的是 -DPCAP_SAMPLE_DIR="E:/Qt/pcap/NPC/samples"
DEFINES += PCAP_SAMPLE_DIR=\\\"$$PWD/samples\\\"

SOURCES += main.cpp\
        widget.cpp

HEADERS  += widget.h
