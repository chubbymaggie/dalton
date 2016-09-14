//
// Created by root on 07/09/16.
//
#include <stdlib.h>
#include "dalton.h"
#include <stdio.h>
#include <glib.h>

DaltonScriptInfo *daltonInfo;

int xrefCount = 0;
int tagsCount = 0;
int addPreferencesCount = 0;
int SecurityMessagesCount = 0;

void initializeDaltonInfo()
{
    daltonInfo = (DaltonScriptInfo *)malloc(sizeof(DaltonScriptInfo));
    daltonInfo->ScriptCopyright = "";
    daltonInfo->ScriptDescription = "";
    daltonInfo->ScriptFamily = "";
    daltonInfo->ScriptId = "";
    daltonInfo->ScriptName ="";
    daltonInfo->ScriptOid = "";
    daltonInfo->ScriptSummary = "";
    daltonInfo->ScriptVersion = "";
    daltonInfo->Success = 0;


}

void setDaltonVersion(char *version)
{
    daltonInfo->ScriptVersion = g_strdup(version);

}
