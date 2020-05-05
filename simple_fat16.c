#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>

#define FUSE_USE_VERSION 26
#include <fuse.h>

#include "fat16.h"

char *FAT_FILE_NAME = "fat16.img";

/* 将扇区号为secnum的扇区读到buffer中 */
void sector_read(FILE *fd, unsigned int secnum, void *buffer)
{
  fseek(fd, BYTES_PER_SECTOR * secnum, SEEK_SET);
  fread(buffer, BYTES_PER_SECTOR, 1, fd);
}

/** TODO:
 * 将输入路径按“/”分割成多个字符串，并按照FAT文件名格式转换字符串
 * 
 * Hint1:假设pathInput为“/dir1/dir2/file.txt”，则将其分割成“dir1”，“dir2”，“file.txt”，
 *      每个字符串转换成长度为11的FAT格式的文件名，如“file.txt”转换成“FILE    TXT”，
 *      返回转换后的字符串数组，并将*pathDepth_ret设置为3
 * Hint2:可能会出现过长的字符串输入，如“/.Trash-1000”，需要自行截断字符串
**/

char **path_split(char *pathInput, int *pathDepth_ret)
{
    int pathDepth = 1;
    char **pathchange = malloc(pathDepth * sizeof(char *));
    int len,i,j,k,pathnum=0,m=0,n=0;
    len=strlen(pathInput);
    for(i=0;i<len;i++){
	if(pathInput[i]!='/')
            continue;
	else
            pathnum++;
    }
    *pathDepth_ret=pathnum;
    pathDepth=pathnum;
    for(i=0;i<pathnum;i++)
       pathchange[i]=(char *)malloc(MAX_SHORT_NAME_LEN *sizeof(char));
    char pathdiv[pathnum][30],a[pathnum][30],b[pathnum][30];
    for(i=1;i<len;i++){
	if(pathInput[i]!='/'){
	    pathdiv[m][n]=pathInput[i];
	    n++;
	}
	else{
	     pathdiv[m][n]='\0';
	     m++;
	     n=0;
        }
    }
   pathdiv[m][n]='\0';
    for(i=0;i<pathnum;i++){
    k=0;
	for(j=0;j<strlen(pathdiv[i]);j++){
		b[i][0]='\0';
	    if(pathdiv[i][j]!='.')
	        a[i][j]=pathdiv[i][j];	    
	    else{
		a[i][j]='\0';
		j++;
		for(k=j;k<strlen(pathdiv[i]);k++){
		  b[i][k-j]=pathdiv[i][k];
		}
		b[i][k-j]='\0';
		break;
	    }
	}
        a[i][j]='\0';	
	if(strlen(a[i])<8){
	   for(j=0;j<strlen(a[i]);j++){	   
	      if(a[i][j]>='a' && a[i][j]<='z')
		  pathchange[i][j]=toupper(a[i][j]);
	      else
		  pathchange[i][j]=a[i][j];
           }
           for(k=j;k<8;k++)
	      pathchange[i][k]=' ';
	}
	else{
	    for(j=0;j<8;j++){	   
	      if(a[i][j]>='a' && a[i][j]<='z')
		  pathchange[i][j]=toupper(a[i][j]);
	      else
		  pathchange[i][j]=a[i][j];
           }
	}
	if(strlen(b[i])<3){
	   for(j=0;j<strlen(b[i]);j++){	   
	      if(b[i][j]>='a' && b[i][j]<='z')
		  pathchange[i][8+j]=toupper(b[i][j]);
	      else
		  pathchange[i][8+j]=b[i][j];
           }
           for(k=j;k<3;k++)
	      pathchange[i][k+8]=' ';
	}
	else{
	    for(j=0;j<3;j++){	   
	      if(b[i][j]>='a' && b[i][j]<='z')
		  pathchange[i][8+j]=toupper(b[i][j]);
	      else
		  pathchange[i][8+j]=b[i][j];
           }
	}
     }
    for(i=0;i<pathnum;i++){
	pathchange[i][11]='\0';
    }
    return pathchange;
}


/** TODO:
 * 将FAT文件名格式解码成原始的文件名
 * 
 * Hint:假设path是“FILE    TXT”，则返回"file.txt"
**/

BYTE *path_decode(BYTE *path)
{
  BYTE *path_pre = malloc(MAX_SHORT_NAME_LEN * sizeof(BYTE));
  int i,j,k,len;
//  char path_pre[12];
  len=strlen(path);
  for(i=0;i<8;i++){
     if(path[i]>='A' && path[i]<='Z')
        path_pre[i]=tolower(path[i]);
     else{
	if(path[i]!=' ')
	   path_pre[i]=path[i];
	else{
	   break;
	}
     }
  }
  j=i; 
     if(path[8]==' '){
	path_pre[j]='\0';
     }
     else{
	path_pre[j]='.';
	j++;
       for(i=8;i<11;i++){
        if(path[i]>='A' && path[i]<='Z')
           path_pre[j++]=tolower(path[i]);
        else{
	   if(path[i]!=' ')
	      path_pre[j++]=path[i];
	   else{
	      break;
	    }
	 }
      }
   }
   path_pre[j]='\0';
  return path_pre;
}


FAT16 *pre_init_fat16(void)
{

  FILE *fd;
  FAT16 *fat16_ins;

  fd = fopen(FAT_FILE_NAME, "rb");

  if (fd == NULL)
  {
    fprintf(stderr, "Missing FAT16 image file!\n");
    exit(EXIT_FAILURE);
  }

  fat16_ins = malloc(sizeof(FAT16));
  fat16_ins->fd = fd;


  BYTE buffer[BYTES_PER_SECTOR];
  fread(fat16_ins->Bpb.BS_jmpBoot,sizeof(BYTE),0x200,fd);
  fat16_ins->FirstRootDirSecNum=fat16_ins->Bpb.BPB_RsvdSecCnt+fat16_ins->Bpb.BPB_FATSz16*fat16_ins->Bpb.BPB_NumFATS;
  fat16_ins->FirstDataSector=fat16_ins->FirstRootDirSecNum + BYTES_PER_DIR*fat16_ins->Bpb.BPB_RootEntCnt/fat16_ins->Bpb.BPB_BytsPerSec;
  return fat16_ins;
}


/** TODO:
 * 返回簇号为ClusterN对应的FAT表项
**/
WORD fat_entry_by_cluster(FAT16 *fat16_ins, WORD ClusterN)
{
  BYTE sector_buffer[BYTES_PER_SECTOR];
  int clusternum=fat16_ins->Bpb.BPB_RsvdSecCnt+ClusterN*2/BYTES_PER_SECTOR;
  int offset=ClusterN*2%BYTES_PER_SECTOR;
  WORD FAT_content;
  sector_read(fat16_ins->fd,clusternum,sector_buffer);
  FAT_content=(WORD)sector_buffer[offset+1]*0x0100 + (WORD)sector_buffer[offset];
  return FAT_content;
}


/**
 * 根据簇号ClusterN，获取其对应的第一个扇区的扇区号和数据，以及对应的FAT表项
**/
void first_sector_by_cluster(FAT16 *fat16_ins, WORD ClusterN, WORD *FatClusEntryVal, WORD *FirstSectorofCluster, BYTE *buffer)
{
  *FatClusEntryVal = fat_entry_by_cluster(fat16_ins, ClusterN);
  *FirstSectorofCluster = ((ClusterN - 2) * fat16_ins->Bpb.BPB_SecPerClus) + fat16_ins->FirstDataSector;

  sector_read(fat16_ins->fd, *FirstSectorofCluster, buffer);
}

/**
 * 从root directory开始，查找path对应的文件或目录，找到返回0，没找到返回1，并将Dir填充为查找到的对应目录项
 * 
 * Hint: 假设path是“/dir1/dir2/file”，则先在root directory中查找名为dir1的目录，
 *       然后在dir1中查找名为dir2的目录，最后在dir2中查找名为file的文件，找到则返回0，并且将file的目录项数据写入到参数Dir对应的DIR_ENTRY中
**/



int find_root(FAT16 *fat16_ins, DIR_ENTRY *Dir, const char *path)
{
  int pathDepth;
  char **paths = path_split((char *)path, &pathDepth);
  BYTE *p;
  int ii,i, j,k,flag=0;
  int RootDirCnt = 1;   
  BYTE buffer[BYTES_PER_SECTOR]; 
  int RootDirSectors = (32*fat16_ins->Bpb.BPB_RootEntCnt+fat16_ins->Bpb.BPB_BytsPerSec-1)/fat16_ins->Bpb.BPB_BytsPerSec;

  for(ii=0;ii<RootDirSectors;ii++){
  sector_read(fat16_ins->fd, fat16_ins->FirstRootDirSecNum+ii, buffer);
  for (i = 0; i < fat16_ins->Bpb.BPB_BytsPerSec/RootDirSectors; i++){  
   p=&buffer[i*BYTES_PER_DIR];
   *Dir=*(DIR_ENTRY*)p;
    if(Dir->DIR_Name[0]==0x00 || Dir->DIR_Name[0]==0xe5)break;
    if(!strncmp(paths[0],Dir->DIR_Name,11)&&pathDepth>1)
        return find_subdir(fat16_ins, Dir, paths, pathDepth, 1);
    else if(!strncmp(paths[0],Dir->DIR_Name,11)&&pathDepth==1)
        return 0;
  }
}
  return 1;
}


int find_subdir(FAT16 *fat16_ins, DIR_ENTRY *Dir, char **paths, int pathDepth, int curDepth)
{
  int ii,i, j,flag,m;
  int DirSecCnt = 1;  
    BYTE* p;
  BYTE buffer[BYTES_PER_SECTOR];
  WORD ClusterN, FatClusEntryVal, FirstSectorofCluster;
  ClusterN=Dir->DIR_FstClusLO;
//  FatClusEntryVal = fat_entry_by_cluster(fat16_ins, ClusterN);
  FirstSectorofCluster = ((ClusterN - 2) * fat16_ins->Bpb.BPB_SecPerClus) + fat16_ins->FirstDataSector;
  
//  first_sector_by_cluster(fat16_ins, ClusterN, &FatClusEntryVal, &FirstSectorofCluster, buffer);
  while(ClusterN>=0x0002 && ClusterN<=0xFFEF){      
       for(ii=0;ii<fat16_ins->Bpb.BPB_SecPerClus;ii++){
	   sector_read(fat16_ins->fd, FirstSectorofCluster+ii, buffer);
         for (i = 0; i < BYTES_PER_SECTOR/BYTES_PER_DIR; i++){ 
              p=&buffer[i*BYTES_PER_DIR];
              *Dir=*(DIR_ENTRY*)p;
	     if(Dir->DIR_Name[0]==0x00 || Dir->DIR_Name[0]==0xe5){
		break;
		break;
	     }              
             else if(!strncmp(paths[curDepth],Dir->DIR_Name,11))
                 if(curDepth+1<pathDepth)
                      return find_subdir(fat16_ins, Dir, paths, pathDepth, curDepth+1);		  
		 else
		      return 0;
          }
        }
         
         FatClusEntryVal = fat_entry_by_cluster(fat16_ins, ClusterN);
         ClusterN=FatClusEntryVal;
         FirstSectorofCluster = ((ClusterN - 2) * fat16_ins->Bpb.BPB_SecPerClus) + fat16_ins->FirstDataSector;
    }
      return 1;        
}


/**
 * ------------------------------------------------------------------------------
 * FUSE相关的函数实现
**/

void *fat16_init(struct fuse_conn_info *conn)
{
  struct fuse_context *context;
  context = fuse_get_context();

  return context->private_data;
}

void fat16_destroy(void *data)
{
  free(data);
}

int fat16_getattr(const char *path, struct stat *stbuf)
{
  FAT16 *fat16_ins;

  struct fuse_context *context;
  context = fuse_get_context();
  fat16_ins = (FAT16 *)context->private_data;

  memset(stbuf, 0, sizeof(struct stat));
  stbuf->st_dev = fat16_ins->Bpb.BS_VollID;
  stbuf->st_blksize = BYTES_PER_SECTOR * fat16_ins->Bpb.BPB_SecPerClus;
  stbuf->st_uid = getuid();
  stbuf->st_gid = getgid();

  if (strcmp(path, "/") == 0)
  {
    stbuf->st_mode = S_IFDIR | S_IRWXU;
    stbuf->st_size = 0;
    stbuf->st_blocks = 0;
    stbuf->st_ctime = stbuf->st_atime = stbuf->st_mtime = 0;
  }
  else
  {
    DIR_ENTRY Dir;

    int res = find_root(fat16_ins, &Dir, path);

    if (res == 0)
    {
      if (Dir.DIR_Attr == ATTR_DIRECTORY)
      {
        stbuf->st_mode = S_IFDIR | 0755;
      }
      else
      {
        stbuf->st_mode = S_IFREG | 0755;
      }
      stbuf->st_size = Dir.DIR_FileSize;

      if (stbuf->st_size % stbuf->st_blksize != 0)
      {
        stbuf->st_blocks = (int)(stbuf->st_size / stbuf->st_blksize) + 1;
      }
      else
      {
        stbuf->st_blocks = (int)(stbuf->st_size / stbuf->st_blksize);
      }

      struct tm t;
      memset((char *)&t, 0, sizeof(struct tm));
      t.tm_sec = Dir.DIR_WrtTime & ((1 << 5) - 1);
      t.tm_min = (Dir.DIR_WrtTime >> 5) & ((1 << 6) - 1);
      t.tm_hour = Dir.DIR_WrtTime >> 11;
      t.tm_mday = (Dir.DIR_WrtDate & ((1 << 5) - 1));
      t.tm_mon = (Dir.DIR_WrtDate >> 5) & ((1 << 4) - 1);
      t.tm_year = 80 + (Dir.DIR_WrtDate >> 9);
      stbuf->st_ctime = stbuf->st_atime = stbuf->st_mtime = mktime(&t);
    }
  }
  return 0;
}


int fat16_readdir(const char *path, void *buffer, fuse_fill_dir_t filler,
                  off_t offset, struct fuse_file_info *fi)
{
  FAT16 *Vol;
  BYTE sector_buffer[BYTES_PER_SECTOR];
  int RootDirCnt = 1, DirSecCnt = 1, i;

  struct fuse_context *context;
  context = fuse_get_context();
  Vol = (FAT16 *) context->private_data;

  sector_read(Vol->fd, Vol->FirstRootDirSecNum, sector_buffer);

  if (strcmp(path, "/") == 0) {
    DIR_ENTRY Root;

    for (i = 1; i <= Vol->Bpb.BPB_RootEntCnt; i++) {
      memcpy(&Root, &sector_buffer[((i - 1) * BYTES_PER_DIR) % BYTES_PER_SECTOR], BYTES_PER_DIR);

      
      if (Root.DIR_Name[0] == 0x00 || Root.DIR_Name[0]==0xe5) {
        return 0;
      }
      
      if ((Root.DIR_Attr == ATTR_ARCHIVE || Root.DIR_Attr == ATTR_DIRECTORY) && Root.DIR_Name[0]!=0xE5) {
        const char *filename = (const char *) path_decode(Root.DIR_Name);
        filler(buffer, filename, NULL, 0);
      }
      
      if (i % 16 == 0 && i != Vol->Bpb.BPB_RootEntCnt) {
        sector_read(Vol->fd, Vol->FirstRootDirSecNum + RootDirCnt, sector_buffer);
        RootDirCnt++;
      }
    }
  } else {
    DIR_ENTRY Dir;
    find_root(Vol, &Dir, path);  
    WORD ClusterN = Dir.DIR_FstClusLO;
    WORD FatClusEntryVal = fat_entry_by_cluster(Vol, ClusterN);
    WORD FirstSectorofCluster = ((ClusterN - 2) * Vol->Bpb.BPB_SecPerClus) + Vol->FirstDataSector;

    sector_read(Vol->fd, FirstSectorofCluster, sector_buffer); 
    for (i = 1; Dir.DIR_Name[0] != 0x00 && Dir.DIR_Name[0]!=0xe5 ; i++) {
      if(ClusterN<0x0002 || ClusterN>0xFFEF)
         break;
      memcpy(&Dir, &sector_buffer[((i - 1) * BYTES_PER_DIR) % BYTES_PER_SECTOR], BYTES_PER_DIR);  
      if ((Dir.DIR_Attr == ATTR_ARCHIVE || Dir.DIR_Attr == ATTR_DIRECTORY) && Dir.DIR_Name[0]!=0xE5) {
        const char *filename = (const char *) path_decode(Dir.DIR_Name);
        filler(buffer, filename, NULL, 0);
      }
      if (i % 16 == 0) {   
        if (DirSecCnt < Vol->Bpb.BPB_SecPerClus) {
          sector_read(Vol->fd, FirstSectorofCluster + DirSecCnt, sector_buffer);
          DirSecCnt++;  
        } else {
          if (FatClusEntryVal == 0xffff) {
            return 0;
          }
 
          ClusterN = FatClusEntryVal; 
          FatClusEntryVal = fat_entry_by_cluster(Vol, ClusterN);
          FirstSectorofCluster = ((ClusterN - 2) * Vol->Bpb.BPB_SecPerClus) + Vol->FirstDataSector;
          sector_read(Vol->fd, FirstSectorofCluster, sector_buffer);
          i = 0;
          DirSecCnt = 1;
        }
      }
    }
  }

  return 0;
}

int fat16_read(const char *path, char *buffer, size_t size, off_t offset,
               struct fuse_file_info *fi)
{
  int i, j;
  BYTE *sector_buffer = malloc((size + offset) * sizeof(BYTE));

  FAT16 *Vol;
  struct fuse_context *context;
  context = fuse_get_context();
  Vol = (FAT16 *) context->private_data;

  DIR_ENTRY Dir;
  find_root(Vol, &Dir, path);

  WORD ClusterN = Dir.DIR_FstClusLO;
  WORD FatClusEntryVal = fat_entry_by_cluster(Vol, ClusterN);
  WORD FirstSectorofCluster = ((ClusterN - 2) * Vol->Bpb.BPB_SecPerClus) + Vol->FirstDataSector;

  for (i = 0, j = 0; i < size + offset; i += BYTES_PER_SECTOR, j++) {
    sector_read(Vol->fd, FirstSectorofCluster + j, sector_buffer + i);

    if ((j + 1) % Vol->Bpb.BPB_SecPerClus == 0) {

      ClusterN = FatClusEntryVal;
     if (FatClusEntryVal == 0xffff) {
            break;
          }

      FatClusEntryVal = fat_entry_by_cluster(Vol, ClusterN);

      FirstSectorofCluster = ((ClusterN - 2) * Vol->Bpb.BPB_SecPerClus) + Vol->FirstDataSector;

      j = -1;
    }
  }

  if (offset < Dir.DIR_FileSize) {
    memcpy(buffer, sector_buffer + offset, size);
  } else {
    size = 0;
  }

  free(sector_buffer);
  return size;
}


/**
 * ------------------------------------------------------------------------------
 * 测试函数
**/

void test_path_split() {
  printf("#1 running %s\n", __FUNCTION__);

  char s[][32] = {"/texts", "/dir1/dir2/file.txt", "/.Trash-100"};
  int dr[] = {1, 3, 1};
  char sr[][3][32] = {{"TEXTS      "}, {"DIR1       ", "DIR2       ", "FILE    TXT"}, {"        TRA"}};

  int i, j, r;
  for (i = 0; i < sizeof(dr) / sizeof(dr[0]); i++) {
  
    char **ss = path_split(s[i], &r);
    assert(r == dr[i]);
    for (j = 0; j < dr[i]; j++) {
      printf("%s\n",ss[j]);
      printf("%d\n",strlen(ss[j]));
      assert(strncmp(sr[i][j], ss[j],11) == 0);
      free(ss[j]);
    }
    free(ss);
    printf("test case %d: OK\n", i + 1);
  }

  printf("success in %s\n\n", __FUNCTION__);
}

void test_path_decode() {
  printf("#2 running %s\n", __FUNCTION__);

  char s[][32] = {"..        ", "FILE    TXT", "ABCD    RM "};
  char sr[][32] = {"..", "file.txt", "abcd.rm"};

  int i, j, r;
  for (i = 0; i < sizeof(s) / sizeof(s[0]); i++) {
    char *ss = (char *) path_decode(s[i]);
    assert(strcmp(ss, sr[i]) == 0);
    free(ss);
    printf("test case %d: OK\n", i + 1);
  }

  printf("success in %s\n\n", __FUNCTION__);
}

void test_pre_init_fat16() {
  printf("#3 running %s\n", __FUNCTION__);

  FAT16 *fat16_ins = pre_init_fat16();

  assert(fat16_ins->FirstRootDirSecNum == 124);
  assert(fat16_ins->FirstDataSector == 156);
  assert(fat16_ins->Bpb.BPB_RsvdSecCnt == 4);
  assert(fat16_ins->Bpb.BPB_RootEntCnt == 512);
  assert(fat16_ins->Bpb.BS_BootSig == 41);
  assert(fat16_ins->Bpb.BS_VollID == 1576933109);
  assert(fat16_ins->Bpb.Signature_word == 43605);
  
  fclose(fat16_ins->fd);
  free(fat16_ins);
  
  printf("success in %s\n\n", __FUNCTION__);
}

void test_fat_entry_by_cluster() {
  printf("#4 running %s\n", __FUNCTION__);

  FAT16 *fat16_ins = pre_init_fat16();

  int cn[] = {1, 2, 4};
  int ce[] = {65535, 0, 65535};

  int i;
  for (i = 0; i < sizeof(cn) / sizeof(cn[0]); i++) {
    int r = fat_entry_by_cluster(fat16_ins, cn[i]);
    assert(r == ce[i]);
    printf("test case %d: OK\n", i + 1);
  }
  
  fclose(fat16_ins->fd);
  free(fat16_ins);

  printf("success in %s\n\n", __FUNCTION__);
}

void test_find_root() {
  printf("#5 running %s\n", __FUNCTION__);

  FAT16 *fat16_ins = pre_init_fat16();

  char path[][32] = {"/dir1", "/makefile", "/log.c"};
  char names[][32] = {"DIR1       ", "MAKEFILE   ", "LOG     C  "};
  int others[][3] = {{100, 4, 0}, {100, 8, 226}, {100, 3, 517}};

  int i;
  for (i = 0; i < sizeof(path) / sizeof(path[0]); i++) {
    DIR_ENTRY Dir;
    find_root(fat16_ins, &Dir, path[i]);
    assert(strncmp(Dir.DIR_Name, names[i], 11) == 0);
    assert(Dir.DIR_CrtTimeTenth == others[i][0]);
    assert(Dir.DIR_FstClusLO == others[i][1]);
    assert(Dir.DIR_FileSize == others[i][2]);

    printf("test case %d: OK\n", i + 1);
  }
  
  fclose(fat16_ins->fd);
  free(fat16_ins);

  printf("success in %s\n\n", __FUNCTION__);
}

void test_find_subdir() {
  printf("#6 running %s\n", __FUNCTION__);

  FAT16 *fat16_ins = pre_init_fat16();

  char path[][32] = {"/dir1/dir2", "/dir1/dir2/dir3", "/dir1/dir2/dir3/test.c"};
  char names[][32] = {"DIR2       ", "DIR3       ", "TEST    C  "};
  int others[][3] = {{100, 5, 0}, {0, 6, 0}, {0, 7, 517}};

  int i;
  for (i = 0; i < sizeof(path) / sizeof(path[0]); i++) {
    DIR_ENTRY Dir;
    find_root(fat16_ins, &Dir, path[i]);
    assert(strncmp(Dir.DIR_Name, names[i], 11) == 0);
    assert(Dir.DIR_CrtTimeTenth == others[i][0]);
    assert(Dir.DIR_FstClusLO == others[i][1]);
    assert(Dir.DIR_FileSize == others[i][2]);

    printf("test case %d: OK\n", i + 1);
  }
  
  fclose(fat16_ins->fd);
  free(fat16_ins);

  printf("success in %s\n\n", __FUNCTION__);
}


struct fuse_operations fat16_oper = {
    .init = fat16_init,
    .destroy = fat16_destroy,
    .getattr = fat16_getattr,
    .readdir = fat16_readdir,
    .read = fat16_read
    };

int main(int argc, char *argv[])
{
  int ret;

  if (strcmp(argv[1], "--test") == 0) {
    printf("--------------\nrunning test\n--------------\n");
    FAT_FILE_NAME = "fat16_test.img";
    test_path_split();
    test_path_decode();
    test_pre_init_fat16();
    test_fat_entry_by_cluster();
    test_find_root();
    test_find_subdir();
    exit(EXIT_SUCCESS);
  }

  FAT16 *fat16_ins = pre_init_fat16();

  ret = fuse_main(argc, argv, &fat16_oper, fat16_ins);

  return ret;
}
