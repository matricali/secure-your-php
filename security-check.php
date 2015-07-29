<?php

/*

                     Secure Yor PHP
                      Version 0.1
            Copyright (C) 2015 Jorge Matricali

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

function disabled_functions()
{
    static $disabled_fn;
    if ($disabled_fn === null) {
        $df = ini_get('disable_functions');
        $shfb = ini_get('suhosin.executor.func.blacklist');
        $fn_list = array_map('trim', explode(',', "$df,$shfb"));
        $disabled_fn = array_filter($fn_list, create_function('$value', 'return $value !== "";'));
    }
    return $disabled_fn;
}

$security_checks = array(
    'Loaded Extensions' => function () {
        return implode(', ', get_loaded_extensions());
    },
    'Running platform' => function () {
        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            return 'This is a server using Windows!';
        } else {
            return PHP_OS;
        }
    },
    'safe_mode' => function () {
        return ini_get('safe_mode');
    },
    'Can view /etc/passwd' => function () {
        return !is_readable('/etc/passwd');
    },
    'Can view /etc/shadow' => function () {
        return !is_readable('/etc/shadow');
    },
    'Shell via "system" command' => function () {
        return !is_callable('system') && !in_array('system', disabled_functions());
    },
    'Shell via "shell_exec" command' => function () {
        return !is_callable('shell_exec') && !in_array('shell_exec', disabled_functions());
    },
    'Shell via "exec" command' => function () {
        return !is_callable('exec') && !in_array('exec', disabled_functions());
    },
    'Shell via "passthru" command' => function () {
        return !is_callable('passthru') && !in_array('passthru', disabled_functions());
    },
    'Shell via "proc_open" command' => function () {
        return !is_callable('proc_open') && !in_array('proc_open', disabled_functions());
    },
    'Shell via "popen" command' => function () {
        return !is_callable('popen') && !in_array('popen', disabled_functions());
    }
);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Secure your PHP v0.1</title>
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.0.0/css/bootstrap.min.css" rel="stylesheet" />
    <!--[if lt IE 9]>
      <script src="https://oss.maxcdn.com/html5shiv/3.7.3/html5shiv.min.js"></script>
      <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
    <![endif]-->
</head>
<body>
  <div class="container">
      <h1 class="page-header">Secure your PHP v0.1</h1>
      <div class="table-responsive">
          <table class="table table-bordered" border="1">
              <thead><tr><th>Check</th><th>Status</th></tr></thead>
              <tbody>
              <?php
              foreach ($security_checks as $security_check => $func) {
                  if (is_callable($func)) {
                      $ret = $func();
                      echo '<tr><td>', $security_check, '</td>';
                      echo '<td>';
                      if (!$ret) {
                          echo '<i class="glyphicon glyphicon-remove"></i> <span class="text-danger">VULNERABLE</span>';
                      } elseif ($ret === true) {
                          echo '<i class="glyphicon glyphicon-ok"></i> <span class="text-success">PASSED</span>';
                      } else {
                          echo $ret;
                      }
                      echo '</td></tr>';
                  }
              }
              ?>
              </tbody>
          </table>
      </div>
  </div>

  <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
  <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.0.0/js/bootstrap.min.js"></script>
</body>
</html>
