# Security
Security Alcatraz Framework


```sh
CREATE TABLE users (
        id int primary key auto_increment,
        login varchar(100) unique not null,
        pass varchar(100) not null,
        lastAccess timestamp,
        activated tinyint(1) not null default 0
);
```

After: 

```sh

use Alcatraz\Owl\Generator\ClassGenerator;

$generator = new ClassGenerator();
$generator->run();

```

Copy Users.php in path/to/project/Application/Entities/Generator to path/to/project/Application/Entities

Open file path/to/project/vendor/alcatraz/kernel/Alcatraz/Kernel/Controller.php and paste code in method __construct()

```sh
use Alcatraz\Security\Security;

class Controller {
 
    function __construct(){
        Security::verifySession();
    }

... [rest of the code]

```