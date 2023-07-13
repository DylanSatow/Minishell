#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <limits.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/wait.h>

#define BRIGHTBLUE "\x1b[34;1m"
#define DEFAULT    "\x1b[0m"

volatile sig_atomic_t signal_val = 0;

char **oldTokens;
char **tokens;
char ***commands;
int numberOfCommands;
bool oldAllocated = false;
bool newAllocated = false;
bool commandAllocated = false;

void catch_signal(int sig) {
    signal_val = sig;
}
void clean_old(){
    if (oldAllocated){
        int increments = 0;
        while (*oldTokens != NULL){
            increments++;
            free(*oldTokens++);
        }
        oldTokens -= increments;
        free(oldTokens);
    }
    oldAllocated = false;
}
void clean_new(){
    if (newAllocated){
        int increments = 0;
        while (*tokens!= NULL){
            increments++;
            free(*tokens++);
        }
        tokens -= increments;
        free(tokens);
    }
    newAllocated = false;
}
void clean_commands(){
    if (commandAllocated){
        for (int i = 0; i < numberOfCommands; i++){
            free(*commands++);
        }
        commands -= numberOfCommands;
        free(commands);
    }
    commandAllocated = false;
}
void memory_cleanup(){
    clean_old();
    clean_new(); 
    clean_commands(); 
}
int count_tokens (char *str){
    char cur;
    int tokenc= 0;
    bool inString = false;
    bool inToken = false;
    while ((cur = *str++) != '\0'){
        if (inString){
            if (cur == '"'){
                inString = false;
                tokenc++;
            }
        }
        else if (cur == '"'){
            if (inToken){
                inToken = false;
            }
            inString = true;
        }
        else if (cur == ' '){
            if (inToken){
                tokenc++;
                inToken = false;
            }
        }
        else {
            if (!inToken){
                inToken = true;
            }
        }
    }
    if (inToken){
        tokenc++;
    }
    if (inString){
        fprintf(stderr,"Error: Missing double quote\n");
        return -1;
    }
    return tokenc;
}
void malloc_check(void *ptr){
    if (ptr == NULL){
        perror("malloc()");
        exit(EXIT_FAILURE);
    }
}
void process_str_tokens(int tokenc, int * trueCount){
    int indicesToPrune[tokenc];
    int tokenLengths[tokenc];
    for (int i = 0; i < tokenc; i++){
        if (**(oldTokens+i)=='"'){
            indicesToPrune[i] = 1;
            tokenLengths[i]=strlen(*(oldTokens+i));
        }
        else{
            indicesToPrune[i] = 0;
        }
    }

    int newLen = tokenc;
    for (int i = 0; i < tokenc; i++){
        if (indicesToPrune[i]){
            int pruning = 0;
            for (int j = i+1; j < tokenc; j++){
                if (indicesToPrune[j]){
                    pruning+=1;
                }
                else{
                    break;
                }
            }
            if (pruning == 0){
                indicesToPrune[i] = 0;
            }
            else{
                indicesToPrune[i] = pruning;
                for (int k = pruning; k > 0; k--){
                    indicesToPrune[i+k] = 0;
                }
            }
            newLen-=pruning;
            i+=(pruning+1);
        }
    }
    tokens = malloc(sizeof(char *)*(newLen+1));
    malloc_check((void *)(tokens));
    int newTokI = 0;
    for (int i = 0; i < tokenc; i++){
        int pruning;
        if ((pruning = indicesToPrune[i])){
            int newLength=0;
            for (int j = i; j <= i+pruning; j++){
                newLength+=tokenLengths[j];
            }
            newLength-=((pruning+1)*2);
            char *prunedStr = malloc(newLength+1);
            malloc_check((void *)(prunedStr));
            int pointerI = 0;
            for (int k = i; k <= i+pruning; k++){
                strncpy(prunedStr+pointerI,*(oldTokens+k)+1,tokenLengths[k]-2); 
                pointerI+=(tokenLengths[k]-2); 
            }
            *(prunedStr+pointerI) = '\0';
            *(tokens+newTokI++) = prunedStr;
            i+=pruning;
        }
        else{
            char * strippedStr;
            char * strToWrite = *(oldTokens+i);
            if (*strToWrite == '"'){
                strippedStr = malloc(strlen(strToWrite)-2+1);
                malloc_check((void *)(strippedStr));
                strToWrite++;
                while (*strToWrite != '"'){
                    *strippedStr++ = *strToWrite++;
                }
                *strippedStr = '\0';
            }
            else{
                strippedStr = malloc(strlen(strToWrite) + 1);
                malloc_check((void *)(strippedStr));
                strcpy(strippedStr, strToWrite);
            }
            *(tokens+newTokI++) = strippedStr;
        }
   }
     *(tokens+newTokI) = NULL;
   *trueCount = newLen;
}
void tokenizer (char *str, int tokenc){
    oldTokens = malloc((tokenc + 1)*sizeof(char *));
    malloc_check((void *)(oldTokens));
    char cur;
    int tokensWritten = 0;
    bool inString = false;
    bool inToken = false;
    int tokenSize = 0;
    char *tokenP;

    while ((cur = *str++) != '\0' && tokensWritten != tokenc){
        if (inString){
            if (cur == '"'){
                inString = false;
                tokenSize++;
                char *token = malloc(tokenSize +1);
                malloc_check((void *)(token));
                strncpy(token, tokenP, tokenSize);
                *(token+tokenSize) = '\0';
                *(oldTokens+tokensWritten) = token;
                tokensWritten++;
            }
            else{
                tokenSize++;
            }
        }
        else if (cur == '"'){
            tokenP = str-1;
            tokenSize = 1;
            inString = true;
            if (inToken){
                inToken=false;
            }
        }
        else if (cur == ' '){
            if (inToken){
                char *token = malloc(tokenSize +1);
                malloc_check((void *)(token));
                strncpy(token, tokenP, tokenSize);
                *(token+tokenSize) = '\0';
                *(oldTokens+tokensWritten) = token;
                tokensWritten++;
                inToken = false;
            }
        }
        else {
            if (!inToken){
                tokenP = str-1;
                tokenSize= 1;
                inToken = true;
            }
            else{
                tokenSize++;
            }
        }
    }
    if (inToken){
        char *token = malloc(tokenSize +1);
        malloc_check((void *)(token));
        strncpy(token, tokenP, tokenSize);
        *(token+tokenSize) = '\0';
        *(oldTokens+tokensWritten) = token;
        tokensWritten++;
        inToken = false;
    }
    *(oldTokens+tokensWritten) = NULL;
}

void change_directory (int tokenc){
    if (tokenc == 1){
        struct passwd* myPass;
        if (!(myPass = getpwuid(getuid()))){
            perror("getpwuid()");
            exit(EXIT_FAILURE);
        }
        if (chdir(myPass->pw_dir) == -1){
            perror("chdir()");
            exit(EXIT_FAILURE);
        }
    }
    else if (tokenc == 2){
        char* dirString = *(tokens+1);
        if (!strcmp("~",dirString)){
            struct passwd* myPass;
            if (!(myPass = getpwuid(getuid()))){
                perror("getpwuid()");
                exit(EXIT_FAILURE);
            }
            if (chdir(myPass->pw_dir) == -1){
                perror("chdir()");
                exit(EXIT_FAILURE);
            }
        }
        else{
            if (strlen(dirString)<=1){
                exit(EXIT_FAILURE);
            }
            if (*dirString=='~'){
                struct passwd* myPass;
                if (!(myPass = getpwuid(getuid()))){
                    perror("getpwuid()");
                    exit(EXIT_FAILURE);
                }
                char expandedDirString[PATH_MAX];
                strcpy(expandedDirString,myPass->pw_dir);
                strcpy(expandedDirString+strlen(expandedDirString), dirString+1);
                if (chdir(expandedDirString) == -1){
                    perror("chdir()");
                    exit(EXIT_FAILURE);
                }
            }
            else{
                if (chdir(dirString) == -1){
                    perror("chdir()");
                    exit(EXIT_FAILURE);
                }
            }
        } 
    }
    else {
        fprintf(stderr, "Error: Too many arguments to cd.\n");
        exit(EXIT_FAILURE);
    }
}
int main() {
    atexit(memory_cleanup);
    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = catch_signal;

    if (sigaction(SIGINT, &action, NULL) == -1) {
        perror("sigaction(SIGINT)");
        return EXIT_FAILURE;
    }
    char buf[PATH_MAX];
    while (true) {
        clean_new();
        clean_commands();
        char current_dir[PATH_MAX];
        if ((getcwd(current_dir, PATH_MAX)) == NULL){
            perror("getcwd()");
            return EXIT_FAILURE;
        }
        printf("%s[%s]$ %s", BRIGHTBLUE, current_dir, DEFAULT);
        fflush(stdout);
        if (fgets(buf, sizeof(buf), stdin) == NULL) {
            if (signal_val) {
                signal_val = 0; 
                printf("\n");    
                fflush(stdout);
                continue;
            } else if (feof(stdin)) {
                printf("\n");
                return EXIT_SUCCESS;
            } else if (ferror(stdin)) {
                printf("\n");
                return EXIT_FAILURE;
            }
        }
        char *eoln = strchr(buf, '\n');
        if (eoln != NULL) {
            *eoln = '\0';
        }
        int tokenc = count_tokens(buf);
        if (tokenc == -1){
            continue;
        }
        tokenizer(buf, tokenc);
        oldAllocated = true;
        int trueCount = 0;
        process_str_tokens(tokenc, &trueCount);
        newAllocated = true;
        clean_old();
        tokenc = trueCount;
        if (!strcmp(buf, "exit")) {
            break;
        }
        if (tokenc == 0){
            continue;
        }
        if (!(strcmp("cd", *tokens))){
            change_directory(tokenc);
            continue;
        }

        int commandPipesCount = 0;
        for (int i = 0; i < tokenc; i++){
            if (!(strcmp(*(tokens+i),"|"))){
                commandPipesCount += 1;
            }
        }
        if (commandPipesCount){
            numberOfCommands = commandPipesCount + 1;
            commands = malloc(numberOfCommands*sizeof(char**));
            malloc_check((void *)(commands));
            commandAllocated = true;
            int countPerCommand = 0;
            int commandIndex = 0;
            int lastPipeIndex;
            for (int i = 0; i < tokenc; i++){
                if (!(strcmp(*(tokens+i),"|"))){
                    char **command = malloc((countPerCommand+1)*(sizeof(char *)));
                    malloc_check((void *)(command));
                    for (int j = 0; j < countPerCommand; j++){
                        *(command+j) = *(tokens+i-countPerCommand+j);
                    }
                    *(command + countPerCommand) = NULL;
                    commands[commandIndex] = command;
                    commandIndex++;
                    lastPipeIndex = i;
                    countPerCommand = 0;
                }
                else{
                    countPerCommand++;
                }
                
            }
            int lastCommandLen = 0;
            int k = 1;
            while (*(tokens+lastPipeIndex+k)!= NULL){
                lastCommandLen++;
                k++;
            }
            char **lastCommand = malloc((lastCommandLen+1)*(sizeof(char *)));
            malloc_check((void *)(lastCommand));
            k = 1;
            while (*(tokens+lastPipeIndex+k)!= NULL){
                *(lastCommand+(k-1)) = *(tokens+lastPipeIndex+k);
                k++;
            }
            *(lastCommand+k-1) = NULL;

            commands[commandIndex] = lastCommand;
            int commandPipes[numberOfCommands][2];
            pid_t pid[numberOfCommands];
            for (int i = 0; i < numberOfCommands; i++){
                if (pipe(commandPipes[i]) < 0){
                    perror("pipe()");
                }
            }
            if ((pid[0] = fork()) == 0) {
                close(commandPipes[0][0]);
                dup2(commandPipes[0][1], STDOUT_FILENO);
                close(commandPipes[0][1]);
                for (int i = 1; i < numberOfCommands; i++){
                    close(commandPipes[i][0]);
                    close(commandPipes[i][1]);
                } 
                execvp(*commands[0] ,commands[0]);
                perror("execvp()");
                return EXIT_FAILURE;
            }
            else if (pid[0] < 0){
                perror("fork()");
                return EXIT_FAILURE;
            }

            for (int i = 1; i < numberOfCommands -1; i++){
                if ((pid[i] = fork()) == 0){
                    close(commandPipes[i-1][1]);
                    dup2(commandPipes[i-1][0], STDIN_FILENO);
                    close(commandPipes[i-1][0]);
                    close(commandPipes[i][0]);
                    dup2(commandPipes[i][1], STDOUT_FILENO);
                    close(commandPipes[i][1]);
                    for (int j = i+1; j < numberOfCommands; j++){
                        close(commandPipes[j][0]);
                        close(commandPipes[j][1]);
                    }
                    for (int k = i-2; k >= 0; k--){
                        close(commandPipes[k][0]);
                        close(commandPipes[k][1]);
                    }
                    execvp(*commands[i] ,commands[i]);
                    perror("execvp()");
                    return EXIT_FAILURE;
                }
                else if (pid[i] < 0){
                    perror("fork()");
                    return EXIT_FAILURE;
                }

            }
            if ((pid[numberOfCommands-1] = fork()) == 0){
                close(commandPipes[numberOfCommands-2][1]);
                dup2(commandPipes[numberOfCommands-2][0], STDIN_FILENO);
                close(commandPipes[numberOfCommands-2][0]);
                close(commandPipes[numberOfCommands-1][0]);
                dup2(commandPipes[numberOfCommands-1][1], STDOUT_FILENO);
                close(commandPipes[numberOfCommands-1][1]);
                for (int i = numberOfCommands-3; i >=0; i--){
                    close(commandPipes[i][0]);
                    close(commandPipes[i][1]);
                }
                execvp(*commands[numberOfCommands-1] ,commands[numberOfCommands-1]);
                perror("execvp()");
                return EXIT_FAILURE;
            }
            else if (pid[numberOfCommands-1] < 0){
                    perror("fork()");
                    return EXIT_FAILURE;
            }

            close(commandPipes[0][1]);
            close(commandPipes[0][0]);
            for (int i = 1; i < numberOfCommands -1; i++){
                close(commandPipes[i][0]);
                close(commandPipes[i][1]);
            }
            close(commandPipes[numberOfCommands-1][1]);
            int save_std;
            save_std = dup(STDIN_FILENO);
            dup2(commandPipes[numberOfCommands-1][0],STDIN_FILENO);
            close(commandPipes[numberOfCommands-1][0]);
            for (int i = 0; i < numberOfCommands; i++){
                int status;
                if (waitpid(pid[i], &status, 0) == -1){
                    if (signal_val) {
                        signal_val = 0; 
                        printf("\n");
                        fflush(stdout);
                        continue;
                    }
                    perror("waitpid()");
                    exit(EXIT_FAILURE);
                }
            }
            ssize_t bytes_read;
            char buf[BUFSIZ];
            memset(buf, 0, BUFSIZ);
            int lines_read = 0;
            char *cur = buf;
            char *newLine;
            while ((bytes_read = read(STDIN_FILENO, buf, BUFSIZ-1)) > 0){
                cur = buf;
                while((newLine =strchr(cur,'\n'))) {
                    cur = newLine + 1;
                    lines_read++;
                }
                if (write(STDOUT_FILENO, buf, bytes_read) == -1){
                    if (signal_val){
                        signal_val = 0;
                        break;
                    }
                    perror("write()");
                    return EXIT_FAILURE;
                }
            }
            if (bytes_read == -1){
                if (signal_val){
                    signal_val = 0;
                    break;
                }
                perror("write()");
                return EXIT_FAILURE;
            }
            dup2(save_std, STDIN_FILENO);

        }
        
        else {
            pid_t pid;
            if ((pid = fork())==0){
                execvp(*tokens, tokens);
                perror("execvp()");
                return EXIT_FAILURE;
            }
            else if (pid < 0){
                perror("fork()");
                return EXIT_FAILURE;
            }
            int status;
            if (waitpid(pid, &status, 0)==-1){
                if (signal_val) {
                    signal_val = 0; 
                    printf("\n");
                    fflush(stdout);
                    continue;
                }
                perror("waitpid()");
                exit(EXIT_FAILURE);
            }
        }
    }
    return EXIT_SUCCESS;
}