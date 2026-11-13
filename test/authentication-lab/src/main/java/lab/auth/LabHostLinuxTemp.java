package lab.auth;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import static lab.auth.LabJson.*;

/** Owns short Linux temporary directories, including recovery after an interrupted guest runner. */
final class LabHostLinuxTemp {
    private LabHostLinuxTemp() {}
    static final String DESCRIPTOR="linux-temp-owner.json";
    static final int MAX_PATH_LENGTH=23;

    static boolean validPath(String path) { return path!=null&&path.matches("/tmp/bpsh-[0-9a-f]{13}")&&path.length()<=MAX_PATH_LENGTH; }

    record Owner(String root,UUID invocation,UUID nonce,long pid,long startedEpochMs) {
        Owner {
            Objects.requireNonNull(invocation);Objects.requireNonNull(nonce);
            LabHostInputs.guestAbsolute(root,"linux");
            require(!root.endsWith("/")&&pid>0&&startedEpochMs>0,"HOST_TEMP_IDENTITY");
        }
    }

    private static Owner current(Path root,UUID invocation,UUID nonce) throws IOException {
        Path absolute=root.toAbsolutePath().normalize();
        require(!Files.isSymbolicLink(absolute)&&absolute.toRealPath().equals(absolute),"HOST_TEMP_ROOT");
        var process=ProcessHandle.current();
        return new Owner(absolute.toString(),invocation,nonce,process.pid(),process.info().startInstant().orElseThrow().toEpochMilli());
    }

    static Path create(Path root,UUID invocation,UUID nonce) throws IOException {
        var owner=current(root,invocation,nonce);execute(allocationScript(owner));
        Path descriptor=root.resolve(DESCRIPTOR);require(!Files.isSymbolicLink(descriptor),"HOST_TEMP_DESCRIPTOR");
        String value=text(read(descriptor,4096),"path");require(validPath(value),"HOST_TEMP_PATH");return Path.of(value);
    }

    static void cleanup(Path root,UUID invocation,UUID nonce) throws IOException {
        var owner=current(root,invocation,nonce);execute(script(owner,"cleanup_temp(root,invocation,nonce,pid,started,False)"));
    }

    static String allocationScript(Owner owner) { return script(owner,"allocate_temp(root,invocation,nonce,pid,started)"); }
    private static String script(Owner owner,String action) {
        return pythonFunctions()+"\nroot,invocation,nonce,pid,started="+JSON.toJson(List.of(owner.root(),owner.invocation().toString(),owner.nonce().toString(),owner.pid(),owner.startedEpochMs()))+"\n"+action+"\n";
    }

    private static void execute(String script) throws IOException {
        boolean interrupted=Thread.interrupted();Process process=null;
        try {
            process=new ProcessBuilder("/usr/bin/python3","-c",script).redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
            if(!process.waitFor(20,TimeUnit.SECONDS)||process.exitValue()!=0)throw new IOException("HOST_TEMP_OWNERSHIP");
        }catch(InterruptedException stopped){interrupted=true;throw new IOException("HOST_TEMP_INTERRUPTED");}
        finally {
            if(process!=null&&process.isAlive()) {
                process.destroyForcibly();
                try { process.waitFor(2,TimeUnit.SECONDS); } catch(InterruptedException stopped){interrupted=true;}
            }
            if(interrupted)Thread.currentThread().interrupt();
        }
    }

    /** Shared by normal guest cleanup and the coordinator's exited-owner recovery script. */
    static String pythonFunctions() { return """
            import json,os,pathlib,re,secrets,stat,uuid
            TEMP_DESCRIPTOR='linux-temp-owner.json'
            TEMP_FIELDS={'version','invocationId','runNonce','guestRoot','guestPid','guestStartedEpochMs','uid','path','allocationId'}
            def strict_pairs(pairs):
                result={}
                for key,value in pairs:
                    assert key not in result,'TEMP_JSON_DUPLICATE'
                    result[key]=value
                return result
            def regular_json(path,private=False,parent_fd=None):
                fd=os.open(path if parent_fd is None else pathlib.Path(path).name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent_fd)
                try:
                    info=os.fstat(fd)
                    assert stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1,'TEMP_FILE_OWNER'
                    assert not private or stat.S_IMODE(info.st_mode)==0o600,'TEMP_FILE_MODE'
                    raw=os.read(fd,4097);assert 0<len(raw)<=4096,'TEMP_SIZE'
                    return json.loads(raw.decode('utf-8'),object_pairs_hook=strict_pairs)
                finally:os.close(fd)
            def integer(value,minimum=1):
                assert type(value) is int and value>=minimum,'TEMP_INTEGER'
                return value
            def identity(root,invocation,nonce,pid,started):
                r=pathlib.Path(root)
                assert r.is_absolute() and r.resolve(strict=True)==r and not r.is_symlink(),'TEMP_ROOT'
                assert stat.S_ISDIR(r.lstat().st_mode) and r.lstat().st_uid==os.getuid() and stat.S_IMODE(r.lstat().st_mode)==0o700,'TEMP_ROOT_OWNER'
                assert str(uuid.UUID(invocation))==invocation and str(uuid.UUID(nonce))==nonce,'TEMP_UUID'
                integer(pid);integer(started)
                owner=regular_json(r/'owner.json');begin=regular_json(r/'report/started.json')
                assert type(owner.get('version')) is int and owner=={'version':1,'invocationId':invocation,'platform':'linux','runNonce':nonce,'guestRoot':root},'TEMP_RUN_OWNER'
                assert set(begin)=={'version','invocationId','runNonce','pid','startedEpochMs','executable'},'TEMP_START_FIELDS'
                assert type(begin['version']) is int and begin['version']==1 and begin['invocationId']==invocation and begin['runNonce']==nonce and integer(begin['pid'])==pid and integer(begin['startedEpochMs'])==started,'TEMP_PROCESS_OWNER'
                return r
            def write_exclusive(path,value,parent_fd=None):
                raw=json.dumps(value,separators=(',',':')).encode();assert len(raw)<=4096,'TEMP_SIZE'
                close_parent=parent_fd is None
                if close_parent:parent_fd=os.open(pathlib.Path(path).parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:
                    fd=os.open(pathlib.Path(path).name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent_fd)
                    try:
                        os.fchmod(fd,0o600)
                        with os.fdopen(fd,'wb',closefd=False) as output:output.write(raw);output.flush();os.fsync(fd)
                    finally:os.close(fd)
                    os.fsync(parent_fd)
                finally:
                    if close_parent:os.close(parent_fd)
            def validate_descriptor(value,root,invocation,nonce,pid,started):
                assert set(value)==TEMP_FIELDS and type(value['version']) is int and value['version']==1,'TEMP_FIELDS'
                assert value['invocationId']==invocation and value['runNonce']==nonce and value['guestRoot']==root,'TEMP_IDENTITY'
                assert integer(value['guestPid'])==pid and integer(value['guestStartedEpochMs'])==started,'TEMP_PROCESS'
                assert integer(value['uid'],0)==os.getuid(),'TEMP_UID'
                path=value['path'];assert type(path) is str and len(path)<=23 and re.fullmatch(r'/tmp/bpsh-[0-9a-f]{13}',path),'TEMP_PATH'
                assert str(uuid.UUID(value['allocationId']))==value['allocationId'],'TEMP_ALLOCATION'
                return pathlib.Path(path)
            def allocate_temp(root,invocation,nonce,pid,started):
                r=identity(root,invocation,nonce,pid,started)
                assert os.getppid()==pid,'TEMP_CALLER'
                parent=pathlib.Path('/tmp');info=parent.lstat()
                assert parent.resolve(strict=True)==parent and stat.S_ISDIR(info.st_mode) and info.st_uid==0 and info.st_mode&stat.S_ISVTX,'TEMP_PARENT'
                path=parent/('bpsh-'+secrets.token_hex(7)[:13])
                value={'version':1,'invocationId':invocation,'runNonce':nonce,'guestRoot':root,'guestPid':pid,'guestStartedEpochMs':started,'uid':os.getuid(),'path':str(path),'allocationId':str(uuid.uuid4())}
                # Publish intent first: an interruption can never leave an undiscoverable external root.
                write_exclusive(r/TEMP_DESCRIPTOR,value)
                os.mkdir(path,0o700)
                fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:
                    os.fchmod(fd,0o700);info=os.fstat(fd)
                    assert stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700,'TEMP_DIRECTORY'
                    write_exclusive(path/'owner.json',value,fd)
                    current=path.lstat();assert (current.st_dev,current.st_ino)==(info.st_dev,info.st_ino),'TEMP_DIRECTORY_CHANGED'
                finally:os.close(fd)
            def under_path(value,root):
                return value==root or value.startswith(root+'/')
            def owned_arguments(args,root,path,nonce):
                values=[os.fsdecode(value) for value in args if value]
                if not values:return False
                if under_path(values[0],root):return True
                if '-Dlab.host.burpNonce='+nonce in values:return True
                prefixes=('-Djava.io.tmpdir=','--user-data-dir=','--database=','--metrics-dir=','--crashpad-handler=')
                for value in values[1:]:
                    if under_path(value,path):return True
                    if any(value.startswith(prefix) and under_path(value[len(prefix):],path) for prefix in prefixes):return True
                return False
            def no_owned_processes(r,path,nonce,pid,owner_exited):
                if owner_exited:assert not pathlib.Path('/proc',str(pid)).exists(),'TEMP_GUEST_ALIVE'
                else:assert os.getppid()==pid,'TEMP_CALLER'
                burp=r/'burp-owner.json'
                if os.path.lexists(burp):
                    value=regular_json(burp)
                    assert set(value)=={'pid','nonce','executable','startedEpochMs'} and value['nonce']==nonce,'TEMP_BURP_OWNER'
                    integer(value['startedEpochMs']);assert not pathlib.Path('/proc',str(integer(value['pid']))).exists(),'TEMP_BURP_ALIVE'
                allowed={os.getpid(),os.getppid()}
                if not owner_exited:allowed.add(pid)
                for proc in pathlib.Path('/proc').iterdir():
                    if not proc.name.isdigit() or int(proc.name) in allowed:continue
                    try:
                        if proc.stat().st_uid!=os.getuid():continue
                        with (proc/'cmdline').open('rb') as source:raw=source.read(1048577)
                    except FileNotFoundError:continue
                    assert len(raw)<=1048576,'TEMP_PROCESS_SIZE'
                    args=raw.split(bytes([0]))
                    assert not owned_arguments(args,str(r),str(path),nonce),'TEMP_OWNED_PROCESS_ALIVE'
            def checked_entry(info,device):
                assert info.st_uid==os.getuid() and info.st_dev==device,'TEMP_TREE_OWNER'
                assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 or stat.S_ISDIR(info.st_mode),'TEMP_TREE_TYPE'
            def validate_tree(fd,device,budget,depth=0):
                assert depth<=128,'TEMP_TREE_DEPTH'
                for name in os.listdir(fd):
                    budget[0]+=1;assert budget[0]<=100000,'TEMP_TREE_SIZE'
                    info=os.stat(name,dir_fd=fd,follow_symlinks=False);checked_entry(info,device)
                    if stat.S_ISDIR(info.st_mode):
                        child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                        try:
                            actual=os.fstat(child);assert (actual.st_dev,actual.st_ino)==(info.st_dev,info.st_ino),'TEMP_TREE_CHANGED'
                            validate_tree(child,device,budget,depth+1)
                        finally:os.close(child)
            def remove_contents(fd,device,top=False):
                names=os.listdir(fd)
                # Keep the ownership marker until all other owned content has been removed.
                if top:names=[name for name in names if name!='owner.json']+['owner.json']
                for name in names:
                    info=os.stat(name,dir_fd=fd,follow_symlinks=False);checked_entry(info,device)
                    if stat.S_ISDIR(info.st_mode):
                        child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                        try:
                            assert (os.fstat(child).st_dev,os.fstat(child).st_ino)==(info.st_dev,info.st_ino),'TEMP_TREE_CHANGED'
                            remove_contents(child,device)
                        finally:os.close(child)
                        current=os.stat(name,dir_fd=fd,follow_symlinks=False);assert (current.st_dev,current.st_ino)==(info.st_dev,info.st_ino),'TEMP_TREE_CHANGED'
                        os.rmdir(name,dir_fd=fd)
                    else:os.unlink(name,dir_fd=fd)
            def cleanup_temp(root,invocation,nonce,pid,started,owner_exited):
                r=identity(root,invocation,nonce,pid,started);descriptor=r/TEMP_DESCRIPTOR
                if not os.path.lexists(descriptor):
                    assert not os.path.lexists(r/'burp-owner.json'),'TEMP_DESCRIPTOR_MISSING'
                    return
                value=regular_json(descriptor,True);path=validate_descriptor(value,root,invocation,nonce,pid,started)
                no_owned_processes(r,path,nonce,pid,owner_exited)
                if not os.path.lexists(path):return
                parent=os.open('/tmp',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:
                    fd=os.open(path.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                    try:
                        info=os.fstat(fd);assert info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700,'TEMP_DIRECTORY_OWNER'
                        assert regular_json(path/'owner.json',True,fd)==value,'TEMP_MARKER'
                        validate_tree(fd,info.st_dev,[0]);remove_contents(fd,info.st_dev,True)
                        current=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
                        assert (current.st_dev,current.st_ino)==(info.st_dev,info.st_ino),'TEMP_DIRECTORY_CHANGED'
                        os.rmdir(path.name,dir_fd=parent)
                    finally:os.close(fd)
                finally:os.close(parent)
            """; }
}
