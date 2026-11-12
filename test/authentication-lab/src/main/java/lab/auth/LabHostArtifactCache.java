package lab.auth;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Set;
import static lab.auth.LabJson.*;

/** Two replaceable current-byte slots; every deployment independently verifies its captured hashes. */
final class LabHostArtifactCache {
    static final String OWNER="BPSH_HOST_CURRENT_ARTIFACTS";
    private final LabHostVmTransport transport;
    LabHostArtifactCache(LabHostVmTransport transport){this.transport=transport;}

    void place(LabHostInputs.Vm vm,LabHostInputs.Artifact artifact,String root,String destination,
               Path privateDirectory,String slot,Duration timeout) throws IOException,InterruptedException {
        require(Set.of("product.jar","large-runtime.jar").contains(slot)&&artifact.path().getFileName().toString().endsWith(".jar"),"HOST_CACHE_SLOT");
        long deadline=System.nanoTime()+timeout.toNanos();artifact.verify();
        String directory=LabHostVmTransport.joinGuest(vm.guestRoot(),".artifact-cache",vm.platform());
        String cached=LabHostVmTransport.joinGuest(directory,slot,vm.platform());
        String probe=LabHostVmTransport.joinGuest(root,"cache-"+slot+".json",vm.platform());
        Path local=privateDirectory.resolve("cache-"+slot+".json");
        String script=vm.platform().equals("windows")?windows(vm,artifact,root,directory,cached,destination,probe):
                linux(vm,artifact,root,directory,cached,destination,probe);
        if(reuse(vm,script,probe,local,deadline))return;
        // The cache is never launched. Replace its bytes directly, then verify and copy into the fresh run.
        transport.put(vm,artifact.path(),cached,remaining(deadline,600));
        if(!reuse(vm,script,probe,local,deadline))throw new LabHostVmTransport.Failure("HOST_CACHE_VERIFICATION");
    }
    private boolean reuse(LabHostInputs.Vm vm,String script,String probe,Path local,long deadline) throws IOException,InterruptedException {
        transport.script(vm,script,remaining(deadline,60));transport.get(vm,probe,local,remaining(deadline,30));
        var value=object(read(local,1024),"reused");var reused=value.get("reused");
        require(reused.isJsonPrimitive()&&reused.getAsJsonPrimitive().isBoolean(),"HOST_CACHE_RECEIPT");return reused.getAsBoolean();
    }
    private static Duration remaining(long deadline,long seconds) throws LabHostVmTransport.Failure {
        long left=deadline-System.nanoTime();if(left<=0)throw new LabHostVmTransport.Failure("HOST_CACHE_DEADLINE");
        return Duration.ofNanos(Math.min(left,Duration.ofSeconds(seconds).toNanos()));
    }
    private static String ps(String value){return LabHostVmTransport.powershellQuote(value);}
    private static String windows(LabHostInputs.Vm vm,LabHostInputs.Artifact artifact,String root,String directory,String source,String destination,String probe) {
        return "$ErrorActionPreference='Stop';$base=[IO.Path]::GetFullPath("+ps(vm.guestRoot())+");$dir=[IO.Path]::GetFullPath("+ps(directory)+");"+
                "$run=[IO.Path]::GetFullPath("+ps(root)+");$src="+ps(source)+";$dst=[IO.Path]::GetFullPath("+ps(destination)+");"+
                "if([IO.Path]::GetDirectoryName($dir) -ne $base -or [IO.Path]::GetDirectoryName($run) -ne $base -or [IO.Path]::GetDirectoryName($dst) -ne ($run+'\\assets')){throw 'HOST_CACHE_OWNER'};"+
                "$marker=$dir+'\\owner.json';if(Test-Path -LiteralPath $dir){"+
                "if(-not(Test-Path -LiteralPath $dir -PathType Container) -or ((Get-Item -LiteralPath $dir).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'HOST_CACHE_OWNER'};"+
                "if(-not(Test-Path -LiteralPath $marker -PathType Leaf) -or (Get-Item -LiteralPath $marker).Length -gt 1024){throw 'HOST_CACHE_OWNER'};"+
                "$owner=Get-Content -LiteralPath $marker -Raw|ConvertFrom-Json;if(@($owner.PSObject.Properties).Count -ne 2 -or $owner.version -ne 1 -or $owner.owner -ne "+ps(OWNER)+"){throw 'HOST_CACHE_OWNER'}"+
                "}else{New-Item -ItemType Directory -Path $dir|Out-Null;[IO.File]::WriteAllText($marker,"+ps("{\"version\":1,\"owner\":\""+OWNER+"\"}")+",[Text.UTF8Encoding]::new($false))};"+
                "if((Test-Path -LiteralPath $src) -and ((Get-Item -LiteralPath $src).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'HOST_CACHE_OWNER'};"+
                "$ok=(Test-Path -LiteralPath $src -PathType Leaf) -and (Get-Item -LiteralPath $src).Length -eq "+artifact.bytes()+";"+
                "if($ok){$ok=(Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash.ToLowerInvariant() -eq "+ps(artifact.sha256())+"};"+
                "if($ok){Copy-Item -LiteralPath $src -Destination $dst -Force;$ok=(Get-FileHash -LiteralPath $dst -Algorithm SHA256).Hash.ToLowerInvariant() -eq "+ps(artifact.sha256())+"};"+
                "[IO.File]::WriteAllText("+ps(probe)+",('{\"reused\":'+$ok.ToString().ToLowerInvariant()+'}'),[Text.UTF8Encoding]::new($false))";
    }
    private static String linux(LabHostInputs.Vm vm,LabHostInputs.Artifact artifact,String root,String directory,String source,String destination,String probe) {
        String code="import pathlib,json,hashlib,shutil\nbase=pathlib.Path("+JSON.toJson(vm.guestRoot())+").resolve()\n"+
                "directory=pathlib.Path("+JSON.toJson(directory)+")\nrun=pathlib.Path("+JSON.toJson(root)+").resolve()\n"+
                "source=pathlib.Path("+JSON.toJson(source)+")\ndestination=pathlib.Path("+JSON.toJson(destination)+")\n"+
                "if directory.is_symlink() or directory.resolve().parent!=base or run.parent!=base or destination.resolve().parent!=run/'assets':raise RuntimeError('HOST_CACHE_OWNER')\n"+
                "marker=directory/'owner.json'\nexpected={'version':1,'owner':"+JSON.toJson(OWNER)+"}\n"+
                "if directory.exists():\n if not directory.is_dir() or not marker.is_file() or marker.stat().st_size>1024 or json.loads(marker.read_text())!=expected:raise RuntimeError('HOST_CACHE_OWNER')\n"+
                "else:\n directory.mkdir()\n marker.write_text(json.dumps(expected))\n"+
                "if source.is_symlink():raise RuntimeError('HOST_CACHE_OWNER')\n"+
                "def digest(path):\n with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()\n"+
                "ok=source.is_file() and source.stat().st_size=="+artifact.bytes()+" and digest(source)=="+JSON.toJson(artifact.sha256())+"\n"+
                "if ok:\n shutil.copyfile(source,destination)\n ok=digest(destination)=="+JSON.toJson(artifact.sha256())+"\n"+
                "pathlib.Path("+JSON.toJson(probe)+").write_text(json.dumps({'reused':ok}))\n";
        return "python3 -c "+LabHostVmTransport.shellQuote(code);
    }
}
