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

$security_checks = [
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
    }
];

echo '<pre>';
foreach ($security_checks as $security_check => $func) {
    if (is_callable($func)) {
        $ret = $func();
        echo $security_check, ' ', !$ret ? 'VULNERABLE' : ($ret === true ? 'PASSED' : $ret), PHP_EOL;
    }
}
