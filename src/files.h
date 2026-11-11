#ifndef TUNDRA_FILES_H
#define TUNDRA_FILES_H

#include "rules.h"

#define FILES_MAX 128
#define FILES_NAME_MAX 64
#define FILES_ERR_MAX 320

/* Reads every *.rules file of dir, in lexicographic order, into rs. 0, -2
 * when a file is wrong (ADR-019: usage) or -1 when it cannot be read; err
 * says which and why. */
int files_load(const char *dir, struct ruleset *rs, char err[FILES_ERR_MAX]);

#endif
