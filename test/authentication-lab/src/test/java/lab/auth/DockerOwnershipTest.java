package lab.auth;
import java.io.IOException;import java.util.*;import org.junit.jupiter.api.Test;import static org.junit.jupiter.api.Assertions.*;
class DockerOwnershipTest {
 @Test void realContainerConfigLabelsAndNetworkLabelsBindImmutableIds() {
  var run=UUID.randomUUID();var invocation=UUID.randomUUID();var labels=Map.of("authlab.run",run.toString(),"authlab.invocation",invocation.toString());
  var container=LabRun.JSON.toJsonTree(Map.of("Id","owned-container","Config",Map.of("Labels",labels))).getAsJsonObject();
  var network=LabRun.JSON.toJsonTree(Map.of("Id","owned-network","Labels",labels)).getAsJsonObject();
  assertDoesNotThrow(()->FederationEnvironment.verifyDockerOwner(container,"owned-container",run,invocation));
  assertDoesNotThrow(()->FederationEnvironment.verifyDockerOwner(network,"owned-network",run,invocation));
  assertThrows(IOException.class,()->FederationEnvironment.verifyDockerOwner(container,"foreign-container",run,invocation));
  assertThrows(IOException.class,()->FederationEnvironment.verifyDockerOwner(network,"owned-network",UUID.randomUUID(),invocation));
 }
 @Test void topLevelLabelsCannotOverrideAContainersForeignConfigOwner() {
  var run=UUID.randomUUID();var invocation=UUID.randomUUID();var labels=Map.of("authlab.run",run.toString(),"authlab.invocation",invocation.toString());
  var foreign=Map.of("authlab.run",UUID.randomUUID().toString(),"authlab.invocation",invocation.toString());
  var container=LabRun.JSON.toJsonTree(Map.of("Id","owned","Config",Map.of("Labels",foreign),"Labels",labels)).getAsJsonObject();
  assertThrows(IOException.class,()->FederationEnvironment.verifyDockerOwner(container,"owned",run,invocation));
 }
}
