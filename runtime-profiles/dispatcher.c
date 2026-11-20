// SPDX-License-Identifier: GPL-3.0-or-later
// Compatibility exec boundary, not a VMM. Manifest is compiled, not caller supplied.
#define _GNU_SOURCE
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <unistd.h>

struct Profile { const char *id,*uuid,*disk,*backend_disk; unsigned long long dev,ino;
 const char *kernel,*initrd,*firmware,*socket,*service,*runtime,*libpath;
 int enabled,file_start,file_count,env_start,env_count; };
struct FileHash { const char *path,*sha; };
struct Env { const char *key,*value; };
struct Candidate { const char *profile,*id,*path,*sha; int enabled; };
#include "manifest.inc"
static void fail(const char *s) { fprintf(stderr,"profile refused: %s\n",s); exit(78); }
static int same(const char *a,const char *b) { return a && b && strcmp(a,b)==0; }

// Platform SHA256 utility with fixed absolute path and empty loader environment.
// No shell, no PATH lookup, no eval; pipes and child fds do not change the parent.
#ifndef HASH_TOOL
#define HASH_TOOL "/system/bin/toybox"
#define HASH_TOOL_TOYBOX
#endif
static int hash_ok(const char *path,const char *expected) {
 int fds[2]; if(pipe2(fds,O_CLOEXEC)) return 0;
 pid_t pid=fork(); if(pid<0) { close(fds[0]); close(fds[1]); return 0; }
 if(!pid) {
  if(dup2(fds[1],STDOUT_FILENO)<0) _exit(126);
  close(fds[0]); close(fds[1]);
  char *const args[]={(char*)HASH_TOOL,
#ifdef HASH_TOOL_TOYBOX
   "sha256sum",
#endif
   (char*)path,NULL};
  char *const env[]={"PATH=/system/bin:/usr/bin:/bin",NULL};
  execve(HASH_TOOL,args,env); _exit(126);
 }
 close(fds[1]); char out[65]={0}; size_t n=0; ssize_t got;
 while(n<64 && (got=read(fds[0],out+n,64-n))>0) n+=(size_t)got;
 // Drain to prevent a long pathname from filling the pipe before waitpid.
 char discard[512]; while(read(fds[0],discard,sizeof(discard))>0) {}
 close(fds[0]); int status=0;
 while(waitpid(pid,&status,0)<0) if(errno!=EINTR) return 0;
 int hash_ok_result = n==64 && WIFEXITED(status) && WEXITSTATUS(status)==0 && same(out,expected);
 if(!hash_ok_result) fprintf(stderr,"hash_dbg path=%s n=%zu status=%x out=%.64s expected=%s errno=%d
",path,n,(unsigned)status,out,expected,errno);
 return hash_ok_result;
}
static int regular(const char *path) { struct stat s; return lstat(path,&s)==0 && S_ISREG(s.st_mode); }
static void verify_files(const struct Profile *p) {
 for(int i=p->file_start;i<p->file_start+p->file_count;i++)
  if(!regular(files[i].path)||!hash_ok(files[i].path,files[i].sha)) fail(files[i].path);
}
static struct stat disk_identity(const struct Profile *p) {
 struct stat s,visible; if(lstat(p->backend_disk,&s)||!S_ISREG(s.st_mode)||lstat(p->disk,&visible)||!S_ISREG(visible.st_mode)||s.st_size!=visible.st_size) fail("disk alias mapping invalid");
 int a=open(p->disk,O_RDONLY|O_NOFOLLOW|O_CLOEXEC),b=open(p->backend_disk,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
 if(a<0||b<0) fail("disk alias mapping unreadable");
 unsigned char x[65536],y[65536];
 off_t positions[2]={0,s.st_size>(off_t)sizeof(x)?s.st_size-(off_t)sizeof(x):0};
 size_t count=s.st_size<(off_t)sizeof(x)?(size_t)s.st_size:sizeof(x);
 for(int k=0;k<2;k++) if(pread(a,x,count,positions[k])!=(ssize_t)count||pread(b,y,count,positions[k])!=(ssize_t)count||memcmp(x,y,count)) fail("disk aliases differ");
 close(a); close(b);
 for(size_t i=0;i<sizeof(profiles)/sizeof(*profiles);i++) if(&profiles[i]!=p) {
  struct stat other; if(!stat(profiles[i].backend_disk,&other)&&s.st_dev==other.st_dev&&s.st_ino==other.st_ino) fail("profiles share a disk inode");
 }
 return s;
}
#ifndef LOCK_ROOT
#define LOCK_ROOT "/data/data/cn.classfun.droidvm/run"
#endif
static int take_lock(const char *name) {
 char path[512]; snprintf(path,sizeof(path),"%s/%s.lock",LOCK_ROOT,name);
 int fd=open(path,O_CREAT|O_RDWR|O_NOFOLLOW,0600); struct stat s;
 if(fd<0||fstat(fd,&s)||!S_ISREG(s.st_mode)||s.st_uid!=geteuid()||(s.st_mode&0022)||flock(fd,LOCK_EX|LOCK_NB)) fail("private managed GPU lock unavailable/busy");
 return fd; // no CLOEXEC: selected runtime owns it until the VM exits
}
#ifndef PROC_ROOT
#define PROC_ROOT "/proc"
#endif
static void consume_probe_gate(void) {
 if(!*PROBE_NONCE) return;
 if(geteuid()!=0) fail("TEST_ONLY probe requires root");
 const char *path=LOCK_ROOT "/profile-probe-gate";
 int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC); struct stat s; char nonce[34]={0};
 if(fd<0||fstat(fd,&s)||!S_ISREG(s.st_mode)||s.st_uid!=0||(s.st_mode&0077)||flock(fd,LOCK_EX|LOCK_NB)||read(fd,nonce,sizeof(nonce)-1)!=(ssize_t)strlen(PROBE_NONCE)||!same(nonce,PROBE_NONCE)) fail("TEST_ONLY one-shot root gate missing/invalid");
 if(unlink(path)) fail("TEST_ONLY gate consume failed");
 close(fd);
}
static void refuse_external_open(const struct stat *disk) {
 DIR *proc=opendir(PROC_ROOT); if(!proc) fail("cannot inspect proc");
 struct dirent *entry; char path[512];
 while((entry=readdir(proc))) {
  char *end; long pid=strtol(entry->d_name,&end,10); if(!*entry->d_name||*end||pid==getpid()) continue;
  snprintf(path,sizeof(path),PROC_ROOT "/%ld/fd",pid); DIR *fds=opendir(path);
  if(!fds) { if(errno==ENOENT||errno==ESRCH) continue; closedir(proc); fail("cannot inspect process descriptors"); }
  struct dirent *fd;
  while((fd=readdir(fds))) {
   if(fd->d_name[0]=='.') continue;
   snprintf(path,sizeof(path),PROC_ROOT "/%ld/fd/%s",pid,fd->d_name); struct stat s;
   if(stat(path,&s)) { if(errno==ENOENT||errno==ESRCH) continue; closedir(fds); closedir(proc); fail("cannot inspect descriptor"); }
   if(S_ISREG(s.st_mode)&&s.st_dev==disk->st_dev&&s.st_ino==disk->st_ino) { closedir(fds); closedir(proc); fail("disk already opened by another process"); }
  }
  closedir(fds);
 }
 closedir(proc);
}
static const char *value(int argc,char **argv,int *i,const char *key) {
 size_t n=strlen(key); const char *arg=argv[*i];
 if(!strncmp(arg,key,n)&&arg[n]=='=') return arg+n+1;
 if(same(arg,key)) { if(++*i>=argc||!strncmp(argv[*i],"--",2)) fail("option missing value"); return argv[*i]; }
 return NULL;
}
static int path_value(const char *v,const char *path) {
 size_t n=strlen(path); return !strncmp(v,path,n)&&(v[n]==0||v[n]==',');
}

// GPU identity is best-effort: the profile ABI stays fail-closed, but a missing
// or unreadable host GPU name must not stop a reviewed VM from starting. The
// discovered value only ever becomes one sanitized SMBIOS product-name token.
static char *sanitize_gpu_name(const char *s) {
 char out[64]; size_t n=0; int space=0;
 if(!s) return NULL;
 for(; *s; s++) {
  unsigned char c=(unsigned char)*s;
  if(c==' '||c=='\t'||c=='\r'||c=='\n') { space=1; continue; }
  if(!(isalnum(c)||c=='.'||c=='_'||c=='-'||c=='('||c==')'||c=='+'||c=='/'||c==':')) continue;
  if(space&&n&&n+1<sizeof(out)) out[n++]=' ';
  space=0;
  if(n+1>=sizeof(out)) break;
  out[n++]=(char)c;
 }
 out[n]=0;
 return n?strdup(out):NULL;
}
static char *gpu_name_from_sysfs(void) {
 int fd=open("/sys/class/misc/mali0/device/gpuinfo",O_RDONLY|O_CLOEXEC);
 char buf[256]; ssize_t got;
 if(fd<0) return NULL;
 got=read(fd,buf,sizeof(buf)-1); close(fd);
 if(got<=0) return NULL;
 buf[got]=0;
 return sanitize_gpu_name(buf);
}
// The dispatcher runs as the DroidVM app (untrusted_app), where SELinux denies
// generic sysfs reads. Vulkan enumeration is the app-legal source of the same
// hardware name; it only needs the system loader and a physical-device query.
typedef void *VkInstance;
typedef void *VkPhysicalDevice;
typedef struct { int32_t sType; const void *pNext; uint32_t flags; const void *pApplicationInfo;
 uint32_t enabledLayerCount; const char *const *ppEnabledLayerNames;
 uint32_t enabledExtensionCount; const char *const *ppEnabledExtensionNames; } VkInstanceCreateInfo;
typedef int32_t (*VkCreateInstanceFn)(const VkInstanceCreateInfo*,const void*,VkInstance*);
typedef void (*VkDestroyInstanceFn)(VkInstance,const void*);
typedef int32_t (*VkEnumeratePhysicalDevicesFn)(VkInstance,uint32_t*,VkPhysicalDevice*);
typedef void (*VkGetPhysicalDevicePropertiesFn)(VkPhysicalDevice,void*);
static char *gpu_name_from_vulkan(void) {
 void *lib=dlopen("libvulkan.so",RTLD_NOW|RTLD_LOCAL);
 VkCreateInstanceFn create; VkDestroyInstanceFn destroy; VkEnumeratePhysicalDevicesFn enumerate;
 VkGetPhysicalDevicePropertiesFn properties; VkInstance instance=NULL; char *result=NULL;
 void *sym;
 uint32_t count=0;
 if(!lib) lib=dlopen("libvulkan.so.1",RTLD_NOW|RTLD_LOCAL);
 if(!lib) return NULL;
 sym=dlsym(lib,"vkCreateInstance"); if(!sym) { dlclose(lib); return NULL; } memcpy(&create,&sym,sizeof(create));
 sym=dlsym(lib,"vkDestroyInstance"); if(!sym) { dlclose(lib); return NULL; } memcpy(&destroy,&sym,sizeof(destroy));
 sym=dlsym(lib,"vkEnumeratePhysicalDevices"); if(!sym) { dlclose(lib); return NULL; } memcpy(&enumerate,&sym,sizeof(enumerate));
 sym=dlsym(lib,"vkGetPhysicalDeviceProperties"); if(!sym) { dlclose(lib); return NULL; } memcpy(&properties,&sym,sizeof(properties));
 {
  VkInstanceCreateInfo ci={1,NULL,0,NULL,0,NULL,0,NULL};
  if(create(&ci,NULL,&instance)!=0||!instance) { dlclose(lib); return NULL; }
 }
 if(enumerate(instance,&count,NULL)!=0||count==0) { destroy(instance,NULL); dlclose(lib); return NULL; }
 if(count>32) count=32;
 {
  VkPhysicalDevice *devices=calloc(count,sizeof(*devices));
  uint32_t i;
  if(!devices) { destroy(instance,NULL); dlclose(lib); return NULL; }
  if(enumerate(instance,&count,devices)!=0) { free(devices); destroy(instance,NULL); dlclose(lib); return NULL; }
  for(i=0;i<count&&!result;i++) {
   _Alignas(16) unsigned char props[1024];
   const char *name; size_t n=0;
   memset(props,0,sizeof(props));
   properties(devices[i],props);
   name=(const char *)(props+20); // deviceName follows apiVersion/driverVersion/vendorID/deviceID/deviceType
   while(n<256&&name[n]) n++;
   if(!n||n==256) continue;
   if(strstr(name,"SwiftShader")||strstr(name,"llvmpipe")) continue;
   result=sanitize_gpu_name(name);
  }
  free(devices);
 }
 destroy(instance,NULL);
 dlclose(lib);
 return result;
}
static char *discover_gpu_name(void) {
 char *name=gpu_name_from_sysfs();
 if(!name) name=gpu_name_from_vulkan();
 return name;
}
// Match a key at the top level of a comma-separated key=value list.  Values may
// contain bracketed comma lists (oem-strings), so a plain strstr is not enough.
static int smbios_has_key(const char *value,const char *key) {
 size_t klen=strlen(key); int depth=0; const char *p=value;
 while(*p) {
  const char *start; size_t n;
  while(*p==','&&!depth) p++;
  start=p;
  while(*p&&!(*p==','&&!depth)) {
   if(*p=='[') depth++;
   else if(*p==']'&&depth>0) depth--;
   p++;
  }
  n=(size_t)(p-start);
  if(n>=klen&&!strncmp(start,key,klen)) return 1;
  if(*p==',') p++;
 }
 return 0;
}
// manufacturer=DroidVM is the KMD's trust marker, not a GPU name: the KMD only
// publishes identity when SystemManufacturer is exactly DroidVM and the
// product-name is a real, non-default value.  Both keys are added independently
// and an existing caller-supplied value is never overwritten.
static char *smbios_with_product(const char *value,const char *product) {
 int add_mfr,add_prod; size_t n,p,o,need; char *out;
 if(!product||!*product) return (char *)value;
 add_mfr=!smbios_has_key(value,"manufacturer=");
 add_prod=!smbios_has_key(value,"product-name=");
 if(!add_mfr&&!add_prod) return (char *)value;
 n=strlen(value); p=strlen(product);
 need=(add_mfr?20:0)+(add_prod?13+p:0)+3;
 out=malloc(n+need+1); if(!out) fail("allocation");
 memcpy(out,value,n); o=n;
 if(o&&out[o-1]!=',') out[o++]=',';
 if(add_mfr) {
  memcpy(out+o,"manufacturer=DroidVM",20); o+=20;
  if(add_prod) out[o++]=',';
 }
 if(add_prod) {
  memcpy(out+o,"product-name=",13); o+=13;
  memcpy(out+o,product,p); o+=p;
 }
 out[o]=0;
 return out;
}
static const struct Profile *select_profile(const char *id) {
 for(size_t i=0;i<sizeof(profiles)/sizeof(*profiles);i++) if(same(id,profiles[i].id)) return &profiles[i];
 return NULL;
}
// A candidate only ever replaces the exec target for its own enrolled profile.
static const struct Candidate *find_candidate(const struct Profile *p,const char *id) {
 for(int i=0;i<CANDIDATE_COUNT;i++)
  if(same(p->id,candidates[i].profile)&&same(id,candidates[i].id)) return &candidates[i];
 return NULL;
}
// Parse balanced comma lists; the daemon's displays=[[...]] contains commas.
// PanVK only changes GPU keys. Everything outside that one argv value is untouched.
static char *panvk_gpu(const char *source) {
 size_t len=strlen(source); char *out=calloc(len+512,1); if(!out) fail("allocation");
 const char *fixed="backend=virglrenderer,context-types=virgl2:drm,egl=true,gles=true,surfaceless=true,udmabuf=true,pci-bar-size=4294967296,fixed-blob-mapping=true";
 strcpy(out,fixed); int depth=0; size_t start=0; int displays=0;
 for(size_t i=0;i<=len;i++) {
  char c=source[i]; if(c=='[') depth++; if(c==']'&&--depth<0) fail("GPU brackets");
  if((c==','&&!depth)||!c) {
   size_t n=i-start; const char *t=source+start;
   const char *keys[]={"backend=","context-types=","egl=","gles=","surfaceless=","udmabuf=","pci-bar-size=","fixed-blob-mapping=",NULL};
   int replaced=(n==13&&!strncmp(t,"virglrenderer",13));
   if(n==12&&!strncmp(t,"vulkan=false",12)) replaced=1;
   if(n>=7&&!strncmp(t,"vulkan=",7)&&!replaced) fail("PanVK Vulkan remoting refused");
   for(int k=0;keys[k];k++) if(n>=strlen(keys[k])&&!strncmp(t,keys[k],strlen(keys[k]))) replaced=1;
   if(!replaced) {
    // Explicit small whitelist; never preserve config-file/render-server/runtime paths.
    if(n>=9&&!strncmp(t,"displays=",9)) { if(displays++) fail("duplicate displays"); }
    else fail("unsupported PanVK GPU key");
    strcat(out,","); strncat(out,t,n);
   }
   start=i+1;
  }
 }
 if(depth||!displays) fail("GPU displays missing/unbalanced");
 return out;
}
static void check_service(const char *v,const struct Profile *p) {
 // Official daemon may append max-queues or display options: identity pair remains exact.
 size_t n=strlen(p->service);
 if(strncmp(v,p->service,n)||(v[n]&&v[n]!=',')) fail("native display service UUID mismatch");
}
static void check_input(const char *v,const struct Profile *p) {
 char needle[200],id[80]; snprintf(id,sizeof(id),"%s",p->uuid);
 snprintf(needle,sizeof(needle),"path=/data/data/cn.classfun.droidvm/run/dvmin_%s",id);
 const char *path=strstr(v,"path="); if(!path||strncmp(path,needle,strlen(needle))||path[strlen(needle)]!='_') fail("input UUID mismatch");
 const char *suffix=path+strlen(needle);
 const char *tags[]={"_ms.sock","_g0_mt.sock","_g0_kbd.sock","_g0_tab.sock",NULL};
 int ok=0; for(int i=0;tags[i];i++) { size_t n=strlen(tags[i]); if(!strncmp(suffix,tags[i],n)&&(suffix[n]==']'||suffix[n]==',')) ok=1; }
 if(!ok) fail("input socket not in whitelist");
}
static int refers(const char *arg,const char *s) { return s && strstr(arg,s); }
static int managed_reference(int argc,char **argv) {
 for(int i=1;i<argc;i++) for(size_t j=0;j<sizeof(profiles)/sizeof(*profiles);j++) {
  const struct Profile *p=&profiles[j];
  if(refers(argv[i],p->disk)||refers(argv[i],p->backend_disk)||refers(argv[i],p->kernel)||refers(argv[i],p->initrd)||refers(argv[i],p->firmware)||refers(argv[i],p->uuid)||refers(argv[i],p->socket)) return 1;
 }
 return 0;
}
int main(int argc,char **argv) {
 const char *id=getenv("DROIDVM_RUNTIME_PROFILE");
 const char *candidate_id=getenv("DROIDVM_RUNTIME_CANDIDATE");
 const struct Profile *p=select_profile(id);
 if(id&&!p) fail("unknown profile (no stock fallback)");
 if(!p) {
  if(candidate_id&&*candidate_id) fail("runtime candidate requires selected profile");
  for(int i=1;i<argc;i++) if(strstr(argv[i],"--droidvm-profile-guard")) fail("profile environment missing");
  if(managed_reference(argc,argv)) fail("managed identity without profile");
  if(!regular(STOCK)||!hash_ok(STOCK,STOCK_HASH)) fail("stock hash mismatch");
  argv[0]=(char*)STOCK; execv(STOCK,argv); fail("stock exec failed");
 }
 if(!p->enabled) fail("profile not enrolled (review manifest blockers)");
 const char *runtime=p->runtime;
 if(candidate_id&&*candidate_id) {
  const struct Candidate *c=find_candidate(p,candidate_id); char why[256];
  if(!c) { snprintf(why,sizeof(why),"runtime candidate not enrolled for this profile: %s",candidate_id); fail(why); }
  if(!c->enabled) { snprintf(why,sizeof(why),"runtime candidate disabled: %s",candidate_id); fail(why); }
  if(!regular(c->path)) { snprintf(why,sizeof(why),"runtime candidate missing/not regular: %s",candidate_id); fail(why); }
  if(!hash_ok(c->path,c->sha)) { snprintf(why,sizeof(why),"runtime candidate hash mismatch: %s",candidate_id); fail(why); }
  runtime=c->path;
  unsetenv("DROIDVM_RUNTIME_CANDIDATE");
 }
 char **out=calloc((size_t)argc*2+8,sizeof(char*)); if(!out) fail("allocation"); out[0]=(char*)runtime;
 int n=1,guards=0,gpu=0,blocks=0,initrds=0,sockets=0,services=0,inputs=0,kernels=0,firmwares=0,prealloc=0,smbios=0;
 char *gpu_name=NULL;
 if(argc<4||!same(argv[1],"--extended-status")||!same(argv[2],"run")) fail("expected --extended-status run");
 for(int i=1;i<argc;i++) {
  const char *arg=argv[i],*v; int before=i;
  if(same(arg,GUARD)) { guards++; continue; }
  if(strstr(arg,"--droidvm-profile-guard")) fail("invalid guard version");
  if((v=value(argc,argv,&i,"--gpu"))) {
   if(gpu++) fail("duplicate GPU");
   out[n++]="--gpu";
   if(same(p->id,"panvk-v1")||same(p->id,"win-panvk-v1")) out[n++]=panvk_gpu(v);
   else { if(!strstr(v,"gfxstream")||strstr(v,"udmabuf=true")||strstr(v,"implicit-render-server=true")||strstr(v,"fixed-blob-mapping=false")) fail("unsafe gfxstream GPU");
    if(strstr(v,"fixed-blob-mapping=true")) out[n++]=(char*)v;
    else { char *x=malloc(strlen(v)+32); if(!x) fail("allocation"); sprintf(x,"%s,fixed-blob-mapping=true",v); out[n++]=x; }
   }
   continue;
  }
  if((v=value(argc,argv,&i,"--smbios"))) {
   if(smbios++) fail("duplicate SMBIOS");
   if(!gpu_name) gpu_name=discover_gpu_name();
   out[n++]="--smbios";
   out[n++]=smbios_with_product(v,gpu_name);
   continue;
  }
  if((v=value(argc,argv,&i,"--block"))) {
   if(blocks++||(!path_value(v,p->disk)&&!path_value(v,p->backend_disk))) fail("disk path mismatch");
   const char *matched=path_value(v,p->disk)?p->disk:p->backend_disk;
   const char *tail=v+strlen(matched); if(*tail&&!same(tail,",lock=false")) fail("unsupported disk options");
   char *block=malloc(strlen(p->backend_disk)+12); if(!block) fail("allocation"); sprintf(block,"%s,lock=false",p->backend_disk);
   out[n++]="--block"; out[n++]=block; continue;
  }
  else if((v=value(argc,argv,&i,"--initrd"))) { if(initrds++||!same(v,p->initrd)) fail("initrd mismatch"); }
  else if((v=value(argc,argv,&i,"--socket"))) { if(sockets++||!same(v,p->socket)) fail("control socket mismatch"); }
  else if((v=value(argc,argv,&i,"--android-display-service"))) { if(services++) fail("duplicate native service"); check_service(v,p); }
  else if((v=value(argc,argv,&i,"--input"))) { check_input(v,p); inputs++; }
  else if((v=value(argc,argv,&i,"--pre-alloc"))) { if(prealloc++||!same(v,"gfx-host-mb=1024")||same(p->id,"panvk-v1")||same(p->id,"win-panvk-v1")) fail("prealloc mismatch"); }
  else if(same(arg,p->kernel)) kernels++;
  else if(p->firmware&&same(arg,p->firmware)) firmwares++;
  else if(same(arg,"--extended-status")&&i==1) {}
  else if(same(arg,"run")&&i==2) {}
  else {
   const char *flags[]={"--no-balloon","--no-pmu","--no-usb","--no-rng","--no-smt","--disable-sandbox","--hugepages",NULL};
   const char *options[]={"--name","--mem","--cpus","--hypervisor","--params","--net","--shared-dir","--serial","--swiotlb","--prepare-lend-mthp-mode","--gpu-cgroup-path","--virtio-snd",NULL};
   int ok=0;
   for(int j=0;flags[j];j++) if(same(arg,flags[j])) ok=1;
   for(int j=0;options[j];j++) if((v=value(argc,argv,&i,options[j]))) { ok=1; break; }
   if(!ok) fail("unsupported argument (profile ABI is failclosed)");
  }
  for(int j=before;j<=i;j++) out[n++]=argv[j];
 }
 if(same(p->id,"win-panvk-v1")) {
  if(guards!=1||gpu!=1||blocks!=1||initrds!=0||sockets!=1||services!=1||inputs<1||kernels!=0||firmwares!=1) fail("required identity/guard missing");
 } else if(guards!=1||gpu!=1||blocks!=1||initrds!=1||sockets!=1||services!=1||inputs<1||kernels!=1||firmwares!=0) fail("required identity/guard missing");
 consume_probe_gate();
 (void)take_lock("unified-gpu-profile");
 (void)take_lock(p->uuid);
 struct stat initial=disk_identity(p); refuse_external_open(&initial);
 for(size_t j=0;j<sizeof(profiles)/sizeof(*profiles);j++) if(&profiles[j]!=p) {
  struct stat other; if(stat(profiles[j].backend_disk,&other)) fail("cannot inspect other managed GPU disk");
  refuse_external_open(&other);
 }
 verify_files(p);
 // FUSE has no flock; private GPU + UUID locks provide managed lifetime exclusion.
 int diskfd=open(p->backend_disk,O_RDONLY|O_NOFOLLOW|O_CLOEXEC); if(diskfd<0) fail("managed disk unavailable");
 struct stat ds,now; if(fstat(diskfd,&ds)||lstat(p->backend_disk,&now)||ds.st_dev!=initial.st_dev||ds.st_ino!=initial.st_ino||ds.st_dev!=now.st_dev||ds.st_ino!=now.st_ino) fail("disk changed during validation");
 unsigned char header[24]={0}; ssize_t bytes=pread(diskfd,header,sizeof(header),0);
 int qcow=bytes>=24&&!memcmp(header,"QFI\373",4);
 if(same(p->id,"panvk-v1")||same(p->id,"win-panvk-v1")) {
  if(!qcow) fail("expected independent qcow2 disk");
  for(int k=8;k<20;k++) if(header[k]) fail("qcow2 backing file refused");
 } else if(bytes<4||qcow) fail("expected raw gfxstream disk");
 if(same(p->id,"gfxstream-v1")&&!prealloc) { out[n++]="--pre-alloc"; out[n++]="gfx-host-mb=1024"; }
 out[n]=NULL;
 if(setenv("LD_LIBRARY_PATH",p->libpath,1)) fail("library environment");
 // Never carry the other renderer's ambient tuning into this profile.
 const char *clear[]={"CROSVM_DISPLAY_VULKAN_LIBRARY","CROSVM_ENABLE_VULKANO_GRALLOC","GFXSTREAM_DEVICE_LOCAL_MEMORY_TYPE","DROIDVM_RUNTIME_CANDIDATE",NULL};
 for(int k=0;clear[k];k++) unsetenv(clear[k]);
 // Clear every reviewed renderer key first, then set only this profile's values.
 for(size_t k=0;k<sizeof(envs)/sizeof(*envs);k++) unsetenv(envs[k].key);
 for(int k=p->env_start;k<p->env_start+p->env_count;k++) if(setenv(envs[k].key,envs[k].value,1)) fail("environment");
 // execv preserves inherited serial fds, all unchanged argv and extended exit statuses.
 // /proc/self/exe is now the selected real crosvm, including AAudio `device snd` re-exec.
 execv(runtime,out); fail("runtime exec failed"); return 78;
}
