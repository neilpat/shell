#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <readline/readline.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include  <signal.h>
#include <time.h>

#define COLOR "debug.h"
#include "sfish.h"
#include "debug.h"


void printDir();
void printDir2();
void execute_helper(char *, char*[]);
void main_handler(int);
void main_handler1(int);
void signal_SIGINT(int);
void signal_SIGTSTP(int);
void signal_SIGTSTP_PARENT(int);
void signal_SIGCNT(int);
void signal_SIGCHLD(int);
void execute(char *, char*[]);
bool findSymbol(const char*, int);
int findChar(char* args[], char* c);
int findChar_IArray(char [], char);
char* findText(const char*);
void colorReturn(char*);

char* promptColor = KNRM;
char* resetColor = KNRM;

char* input;

pid_t last_proc_stopped;
pid_t parent_proc_id;
int job_count = 1;

struct bg_jobs{
    int pid;
    int job;
    char* name;
    struct bg_jobs* next;
};
struct bg_jobs *all_jobs = NULL;

void add_job(struct bg_jobs* jb){
    struct bg_jobs *cursor = all_jobs;
    int flag_contains = 0;
    while(cursor != NULL){
        if(cursor->job == jb->job){
            flag_contains = 1;
            break;
        }
        cursor = cursor->next;
    }
    if(flag_contains == 1){

    }
    else{
        jb->next = all_jobs;
        all_jobs = jb;
        job_count++;
    }
}
int get_job(int job_id){
    struct bg_jobs *cursor1;
    cursor1 = all_jobs;
    while(cursor1 != NULL){
        if(cursor1->job == job_id){
            return cursor1->pid;
        }
        cursor1 = cursor1->next;
    }
    return -1;
}
void remove_job(int in_job){
    struct bg_jobs *cursor1, *cursor2;
    cursor1 = all_jobs;
    cursor2 = cursor1->next;
    if(cursor1->job == in_job){
        if(all_jobs->next == NULL){
            all_jobs = NULL;
        }
        else{
            all_jobs = all_jobs->next;
        }
    }
    if(cursor2 == NULL){
        if(cursor1->job == in_job){
            all_jobs = NULL;
        }
    }
    while(cursor2 != NULL){
        if(cursor2->job == in_job){
            cursor1->next = cursor2->next;
            break;
        }
        cursor2 = cursor2->next;
        cursor1 = cursor1->next;
    }
    if(all_jobs == NULL){
        job_count = 1;
    }
}
int remove_job_PID(int in_pid){
    struct bg_jobs *cursor1, *cursor2;
    cursor1 = all_jobs;
    cursor2 = cursor1->next;
    if(cursor1->pid == in_pid){
        if(all_jobs->next == NULL){
            all_jobs = NULL;
        }
        else{
            all_jobs = all_jobs->next;
        }
        return 1;
    }
    if(cursor2 == NULL){
        if(cursor1->pid == in_pid){
            all_jobs = NULL;
            return 1;
        }
    }
    while(cursor2 != NULL){
        if(cursor2->pid == in_pid){
            cursor1->next = cursor2->next;
            return 1;
            break;
        }
        cursor2 = cursor2->next;
        cursor1 = cursor1->next;
    }
    if(all_jobs == NULL){
        job_count = 1;
    }
    return -1;
}
void print_job(struct bg_jobs this_job){
    printf("[%d] %s\n", this_job.job, this_job.name);
}
void print_all_jobs(){
    struct bg_jobs *cursor;
    cursor = all_jobs;
    while(cursor != NULL){
        printf("[%d] %s\n", cursor->job, cursor->name);
        cursor = cursor->next;
    }
}

int currentJob = -1;
int child_status;
char lastDirectory[1000];
int main(int argc, char *argv[], char* envp[]) {

    bool exited = false;

    char currentDirectory[1000];
    lastDirectory[0] = '\0';

    if(!isatty(STDIN_FILENO)) {
        if((rl_outstream = fopen("/dev/null", "w")) == NULL){
            perror("Failed trying to open DEVNULL");
            exit(EXIT_FAILURE);
        }
    }
    if(signal(SIGINT, signal_SIGINT) == SIG_ERR){
        printf("Can't catch main...\n");
    }
    do {
        printDir();
        if(input == NULL) {
            printf("\n");
            continue;
        }

        char copyInput[1000];
        memcpy(copyInput, input, 1000);
        strtok(copyInput, " \t");

        if(strstr(input, "color") != NULL){
            char* argu = strtok(NULL, " ");
            char p[] = "K";
            if(argu != NULL){
                strcat(p, argu);
            }
            colorReturn(p);
        }
        else if(strcmp(copyInput, "cd") == 0){     //IF USER TYPED IN CD
            char* argu = strtok(NULL, " \t");
            if(argu != NULL){
                if(strcmp(argu, "-") == 0){                     //IF USER TYPED IN CD -
                    if(lastDirectory[0] == '\0'){               //IF LASTDIRECTORY WAS NULL
                        continue;
                    }
                    else{
                        chdir(lastDirectory);
                    }
                }
                else if(strcmp(argu, ".") == 0){                //IF USER TYPED IN CD .

                }
                else if(strcmp(argu, "..") == 0){               //IF USER TYPED IN CD ..
                    getcwd(lastDirectory, 1000);
                    getcwd(currentDirectory, 1000);             //CHANGE TO LASTDIRECTORY
                    if(strcmp(currentDirectory, "/home") == 0){
                        chdir("/");
                        continue;
                    }
                    if(strcmp(currentDirectory, "/") == 0){
                        continue;
                    }
                    char copyDir[1000];
                    memcpy(copyDir,currentDirectory, 1000);
                    char * token, * last;
                    last = token = strtok(copyDir, "/");
                    for (;(token = strtok(NULL, "/")) != NULL; last = token){
                    }
                    char *ret;
                    ret = strstr(currentDirectory, last);
                    *(ret - 1) = '\0';
                    if(ret);
                    chdir(currentDirectory);
                }
                else{
                    getcwd(lastDirectory, 1000);                //IF USER TYPED WHERE TO CD WILL GO
                    if(chdir(argu) < 0){
                        printf(BUILTIN_ERROR, "NOT A VALID DIRECTORY");
                    }
                }
            }
            else{
                chdir(getenv("HOME"));
            }
        }
        else if(strcmp(copyInput, "exit") == 0){
            break;
        }
        else if(strcmp(copyInput, "jobs") == 0){
            print_all_jobs();
        }
        else if(strcmp(copyInput, "fg") == 0){
            char* argu = strtok(NULL, " \t");
            if(argu != NULL){
                if(*argu == '%'){
                    ++argu;
                    int job_id = atoi(argu);
                    int pid1 = get_job(job_id);
                    if(pid1 > 0){
                        currentJob = job_id;
                        signal(SIGCHLD, signal_SIGCNT);
                        tcsetpgrp(STDOUT_FILENO, pid1);
                        kill(pid1, SIGCONT);
                        signal(SIGINT, signal_SIGINT);
                        waitpid(pid1, &child_status, WUNTRACED);
                        if(WIFSTOPPED(child_status)){
                            signal_SIGTSTP_PARENT(SIGTSTP);
                        }
                        if(WIFSIGNALED(child_status)){
                            signal_SIGINT(SIGINT);
                        }
                        if(WIFEXITED(child_status)){
                            signal_SIGINT(SIGINT);
                        }
                        tcsetpgrp(STDOUT_FILENO, getpgid(getpid()));
                    }
                    else{
                        printf(BUILTIN_ERROR, "INVLIAD JOB ID");
                    }
                }
                else{
                    printf(BUILTIN_ERROR, "INVALID FORMAT FOR fg");
                }
            }
        }
        else if(strcmp(copyInput, "kill") == 0){
            char* argu = strtok(NULL, " \t");
            if(argu != NULL){
                if(*argu == '%'){
                    ++argu;
                    int job_id = atoi(argu);
                    int pid1 = get_job(job_id);
                    if(pid1 > 0){
                        signal(SIGCHLD, SIG_IGN);
                        remove_job(job_id);
                        kill(pid1, SIGKILL);
                        waitpid(pid1, NULL, 0);
                    }
                    else{
                        printf(BUILTIN_ERROR, "INVALID JOB ID");
                    }
                }
                else{
                    int pid1 = atoi(argu);
                    if(pid1 > 0){
                        signal(SIGCHLD, SIG_IGN);
                        if(remove_job_PID(pid1) < 0){
                            printf(BUILTIN_ERROR, "INVALID PID");
                        }
                        else{
                            kill(pid1, SIGKILL);
                            waitpid(pid1, NULL, 0);
                        }
                    }
                    else{
                        printf(BUILTIN_ERROR, "INVALID PID");
                    }
                }
            }
        }
        else{
            execute_helper(input,argv);
        }
        exited = strcmp(input, "exit") == 0;
        rl_free(input);
    } while(!exited);

    debug("\n%s", "user entered 'exit'");
    return EXIT_SUCCESS;
}
pid_t pid;
pid_t cpid;
char process_name[1000];
void execute_helper(char *cmd, char* argv[]){
    char copyInput2[1000];
    char copyInput[1000];
    char currentDirectory[1000];
    memcpy(copyInput2, cmd, 1000);
    int n = 0;
    int count = 0;
    int symCount1 = 0;
    int symCount2 = 0;
    while(copyInput2[n] != '\0'){
        if((copyInput2[n] != '<') && (copyInput2[n] != '>') && (copyInput2[n] != '|')){
            copyInput[count] = copyInput2[n];
            count++;
            n++;
        }
        else{
            if(copyInput2[n] == '<'){
                symCount1++;
            }
            else{
                symCount2++;
            }
            copyInput[count] = ' ';
            count++;
            copyInput[count] = copyInput2[n];
            count++;
            copyInput[count] = ' ';
            count++;
            n++;
        }
    }
    copyInput[count] = '\0';
    char* argu = strtok(copyInput, " ");
    int i = 0;
    int pos1 = -1;
    int pos2 = -1;
    if(argu != NULL){
        argv[i] = argu;
        i++;
    }
    memcpy(process_name, cmd, 1000);
    while(argu != NULL){
        argu = strtok(NULL, " ");
        argv[i] = argu;
        i++;
    }
    argv[i] = '\0';
    int pipe_flag = 0;
    if(findSymbol(cmd, (int)'|')){
        pipe_flag = 1;
    }
    if(argv[0] != NULL){
        if(strcmp(argv[0], "git") == 0){
            pipe_flag = 2;
        }
    }
    if(pipe_flag == 0){
        if(symCount1 <=1 && symCount2 <=1){
            sigset_t mask, prev;
            signal(SIGTSTP, signal_SIGTSTP_PARENT);
            signal(SIGCHLD, signal_SIGCHLD);
            sigemptyset(&mask);
            sigaddset(&mask, SIGCHLD);
            sigprocmask(SIG_BLOCK, &mask, &prev);
            signal(SIGTTOU, SIG_IGN);

            pid = fork();
            cpid = pid;

            if(pid == 0){
                setpgid(getpid(), getpid());
                tcsetpgrp(STDOUT_FILENO, getpgid(getpid()));

                if(findSymbol(cmd, (int)'<')){
                    char* symbol = "<";
                    pos1 = findChar(argv, symbol);
                    int fd = open(argv[pos1 + 1], O_RDONLY, S_IRWXU);
                    if(fd == -1){
                        printf(EXEC_ERROR, "INVALID FILE");
                        exit(EXIT_SUCCESS);
                    }
                    else{
                        dup2(fd, 0);
                        close(fd);
                    }
                }
                if(findSymbol(cmd, (int)'>')){
                    char* symbol = ">";
                    pos2 = findChar(argv, symbol);
                    int fd = open(argv[pos2 + 1], O_WRONLY | O_TRUNC | O_CREAT, S_IRWXU );
                    if(fd == -1){
                        printf(EXEC_ERROR, "INVALID FILE");
                        exit(EXIT_SUCCESS);
                    }
                    else{
                        dup2(fd, 1);
                        close(fd);
                    }
                }
                if(pos1 != -1){
                    argv[pos1] = '\0';
                }
                if(pos2 != -1){
                    argv[pos2] = '\0';
                }
                if(strcmp(argv[0], "help") == 0){                    //IF USER TYPES IN HELP
                    printf("\nHELP MENU: \nFOR BEST PERFORMANCE USE FULL SCREEN\n PLEASE REFER TO THE ASSIGNMENT DOC TO CHECK COMMANDS!!\n");
                }
                else if(strcmp(argv[0], "pwd") == 0){
                    getcwd(currentDirectory, 1000);
                    printf("%s\n", currentDirectory);
                }
                else{
                    execute(argv[0], argv);
                }
                exit(EXIT_SUCCESS);
            }
            else{
                signal(SIGINT, signal_SIGINT);
                sigsuspend(&prev);
                sigprocmask(SIG_SETMASK, &prev, NULL);
            }
        }
        else{
            printf(SYNTAX_ERROR, "INVALID REDIRECTIONS");
        }
    }
    else if(pipe_flag == 1){
     char copyInput2[1000];
     char copyInput[1000];
     //char currentDirectory[1000];
     memcpy(copyInput2, cmd, 1000);
     int n = 0;
     int count = 0;
     int symCount1 = 0;
     int symCount2 = 0;
     while(copyInput2[n] != '\0'){
        if((copyInput2[n] != '<') && (copyInput2[n] != '>') && (copyInput2[n] != '|')){
            copyInput[count] = copyInput2[n];
            count++;
            n++;
        }
        else{
            if(copyInput2[n] == '<'){
                symCount1++;
            }
            else{
                symCount2++;
            }
            copyInput[count] = ' ';
            count++;
            copyInput[count] = copyInput2[n];
            count++;
            copyInput[count] = ' ';
            count++;
            n++;
        }
    }
    copyInput[count] = '\0';
    int num_pipes = 0;
    char* argu1 = strtok(copyInput, " \t");
    while(argu1 != NULL){
        if(strcmp(argu1,"|") == 0){
            num_pipes++;
        }
        argu1 = strtok(NULL, " \t");
    }
    int pipefd[2*num_pipes];
    pid_t cpid;

    for(int i = 0; i < num_pipes; i++ ){
        if(pipe(pipefd + i * 2) < 0 ){
            perror("pipe");
            exit(EXIT_FAILURE);
        }
    }
    memcpy(copyInput, cmd, 1000);
    char* pipe_argu = strtok(copyInput, "|");
    char* pipe_cmds[1000];
    int arguments = 0;
    while(pipe_argu != NULL){
        pipe_cmds[arguments] = pipe_argu;
        pipe_argu = strtok(NULL, "|");
        arguments++;
    }
    int count1 = 0;
    signal(SIGCHLD, SIG_IGN);
    while(count1 < (num_pipes + 1)){
        char input_argu[1000];
        memcpy(input_argu, pipe_cmds[count1], 1000);
        char* input_array[10];
        int i = 1;
        char* argu = strtok(input_argu, " \t");
        input_array[0] = argu;
        while(argu != NULL){
            argu = strtok(NULL, " \t");
            input_array[i] = argu;
            i++;
        }
        input_array[i] = '\0';

        cpid = fork();
        if (cpid == -1) {
            perror("fork");
            exit(EXIT_FAILURE);
        }
        if(cpid == 0){
            if(count1 != 0){
                if( dup2(pipefd[(count1-1)*2], 0) < 0){
                    perror("pipe");
                    exit(EXIT_FAILURE);
                }
            }
            if(count1 < num_pipes){
                if( dup2(pipefd[count1*2+1], 1) < 0 ){
                    perror("pipe");
                    exit(EXIT_FAILURE);
                }
            }
            for(int i = 0; i < (num_pipes * 2); i++){
                close(pipefd[i]);
            }
                execute(input_array[0], input_array);       //
                exit(EXIT_SUCCESS);
            }else if(cpid < 0){
                perror("pipe");
                exit(EXIT_FAILURE);
            }
            count1++;
        }
        for(int i = 0; i < (num_pipes * 2); i++){
            close(pipefd[i]);
        }
        signal(SIGCHLD, SIG_IGN);
        waitpid(cpid, &child_status, WUNTRACED);
    }
    else if(pipe_flag == 2){
        memcpy(copyInput, cmd, 1000);
        char buf[5000];
        int pipefd[2];
        pipe(pipefd);
        char* input_array[10];
        int i = 1;
        char* argu = strtok(copyInput, " ");
        input_array[0] = argu;
        while(argu != NULL){
            argu = strtok(NULL, " ");
            input_array[i] = argu;
            i++;
        }
        input_array[i] = '\0';
        int count1 = 0;
        while(count1 < 2){
            pid_t cpid = fork();
            if(cpid == 0){
                if(count1 != 0){
                    if( dup2(pipefd[0], 0) < 0){
                        perror("pipe");
                        exit(EXIT_FAILURE);
                    }
                }
                if(count1 < 1){
                    if( dup2(pipefd[1], 1) < 0 ){
                        perror("pipe");
                        exit(EXIT_FAILURE);
                    }
                }
                for(int i = 0; i < 2; i++){
                    close(pipefd[i]);
                }
                if(count1 == 1){
                    while(read(pipefd[0], &buf, 1) > 0);
                }
                else{
                    currentJob = -1;
                    execute(input_array[0], input_array);
                }
                exit(EXIT_SUCCESS);
            }else if(cpid < 0){
                perror("pipe");
                exit(EXIT_FAILURE);
            }
            count1++;
            pid_t ccpid = fork();
            if(ccpid == 0){
                dup2(pipefd[0], 0);
                close(pipefd[0]);
                close(pipefd[1]);
                read(pipefd[0], &buf, 5000);
                exit(EXIT_SUCCESS);
            }
            else{
                pid_t ccpid = fork();
                if(ccpid == 0){
                    dup2(pipefd[1], 1);
                    close(pipefd[0]);
                    close(pipefd[1]);
                    execute(input_array[0], input_array);
                    exit(EXIT_SUCCESS);
                }
            }
        }
        fprintf(stderr, "[[%s]]]\n", buf);
    }
}
void execute(char *argv1, char *argv[]){
    if(execvp(argv1, argv) < 0) {
        dup2(2 , 1);
        printf(EXEC_NOT_FOUND, argv[0]);
        exit(1);
    }
}
void main_handler1(int sig){

}
pid_t old_cpid = -1;
void signal_SIGTSTP_PARENT(int sig){
    tcsetpgrp(STDOUT_FILENO, getpid());
    if(cpid != old_cpid){
        kill(cpid, SIGTSTP);
        struct bg_jobs *process;
        process = (struct bg_jobs*)malloc(sizeof(struct bg_jobs));
        process->pid = cpid;
        if(currentJob != -1){
            process->job = currentJob;
        }
        else{
            process->job = job_count;
            char* nstr = malloc(strlen(process_name));
            strcpy(nstr, process_name);
            process->name = nstr;
        }
        add_job(process);
        print_job(*process);
        old_cpid = cpid;
    }
    tcsetpgrp(STDOUT_FILENO, getpgid(getpid()));
}
void signal_SIGCNT(int sig){

}

void signal_SIGCHLD(int sig){
    //printf("ENTER SIGCHILD\n");
    if(sig == SIGCHLD){
        waitpid(pid, &child_status, WUNTRACED | WCONTINUED);
        if(WIFSTOPPED(child_status)){
            signal_SIGTSTP_PARENT(SIGTSTP);
        }
        if(WIFSIGNALED(child_status)){
            signal_SIGINT(SIGINT);
        }
    }
    tcsetpgrp(STDOUT_FILENO, getpgid(getpid()));
}
void signal_SIGINT(int sig){
    if(sig == SIGINT){
        kill(pid, SIGINT);
    }
    if(currentJob !=-1){
        remove_job(currentJob);
        currentJob = -1;
    }
}
bool findSymbol(const char* s,int c){
    if(strchr(s,c) != NULL){
        return true;
    }
    return false;
}
int findChar(char* argv[], char* c){
    for(int i = 0;*(argv + i)!='\0';i++){
        if(strcmp(*(argv + i), c) == 0){
            return i;
        }
    }
    return -1;
}
int findChar_IArray(char str[], char c){
    for(int i = 0; str[i] != '\0';i++){
        if(str[i] == c){
            return i;
        }
    }
    return -1;
}
void printDir(){
    time_t time1;
    char bf[26];
    struct tm* tm;

    time(&time1);
    tm = localtime(&time1);

    strftime(bf, 26, STRFTIME_RPRMT, tm);

    char currentDirectory[1000];
    getcwd(currentDirectory, 1000);
    int length = 0;
    char string[1000];
    if(strstr(currentDirectory, getenv("HOME")) != NULL){
        memcpy(string, promptColor, 10);
        strcat(string, "~");
        strcat(string, (currentDirectory + strlen(getenv("HOME"))));
        strcat(string,"  :: nirpatel>>");
        strcat(string, resetColor);
        strcat(string, "\e[s");
        length = strlen("~") + strlen(" :: nirpatel>>\e[s") + strlen(currentDirectory + strlen(getenv("HOME")));
        for (int n = 0 ; n < (60 - length) ; n++) {
            strcat(string, " ");
        }
        strcat(string, bf);
        strcat(string, "\e[u");
    }
    else{
        memcpy(string, getcwd(currentDirectory, 1000), 1000);
        strcat(string, ":: nirpatel>>");
    }
    input = readline(string);
}
void printDir2(){
    input = readline("");
}
void colorReturn(char* inputColor){
    if(strcmp(inputColor, "KNRM")==0){
        promptColor = KNRM;
    }
    else if(strcmp(inputColor, "KRED")==0){
        promptColor = KRED;
    }
    else if(strcmp(inputColor, "KGRN")==0){
        promptColor = KGRN;
    }
    else if(strcmp(inputColor, "KYEL")==0){
        promptColor = KYEL;
    }
    else if(strcmp(inputColor, "KBLU")==0){
        promptColor = KBLU;
    }
    else if(strcmp(inputColor, "KMAG")==0){
        promptColor = KMAG;
    }
    else if(strcmp(inputColor, "KCYN")==0){
        promptColor = KCYN;
    }
    else if(strcmp(inputColor, "KBLU")==0){
        promptColor = KBLU;
    }
    else if(strcmp(inputColor, "KBLU")==0){
        promptColor = KBLU;
    }
    else if(strcmp(inputColor, "KBWN")==0){
        promptColor = KBWN;
    }
    else{
        printf(BUILTIN_ERROR, "NOT A VALID COLOR");
    }
}
