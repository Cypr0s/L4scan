#-------------- IPK 1. project -----------------
#	file:	Makefile
# 	Author: Kristian Luptak <xluptak00>
#	date: 	created: 	11.3.2026
#			last edit:	11.3.2026

#compiling
CC=gcc
CFLAGS= -std=gnu17 -pedantic -Wall -Wextra
FILE_LOC= src/
OBJ= 	l4scan.o 	\
		parse.o		\
		interface.o	\
		util.o		\
		hostname.o
OUT= ipk-L4-scan

#utils
DEVSHELL=c

ZIP_NAME=xluptak00



.PHONY: test all clean NixDevShellName zip

# compiling
all: $(OUT)

$(OUT): $(OBJ)
	$(CC) $(CFLAGS) -o $(OUT) $(OBJ)

%.o: $(FILE_LOC)%.c
	$(CC) $(CFLAGS) -o $@ -c $<


# write devShell into stdout
NixDevShellName:
	@echo $(DEVSHELL)

# run automatic tests
test: all

# zip
zip:
	zip -r $(ZIP_NAME).zip Makefile LICENSE CHANGELOG.md README.md tests src -x *.o

# clean
clean:
	rm -rf *.o $(OUT)

