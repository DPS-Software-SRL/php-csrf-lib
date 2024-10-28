<?php

namespace Dps;

/**
 * Summary of DPS_CSRF
 * Genera tokens unicos para CSRF basados en el Script / Usuario / Hora 
 * Los guarda en SESSION para poder ser accedidos y comparados
 * Se usara en Grillas y Formy
 * 
 * @requires $_ENV['SECRET_ANTI_CSRF'] con algun valor aletario 
 */
class CSRF {    
    
    private static $dirname;
    private static $formy_csrf;
    private static $script;
    private static $secret;
    private static $usuario;
    
    public function __construct() {
        if( ! isset( $_ENV['SECRET_ANTI_CSRF'] ) ) {
            throw new \Exception('Crear en .env la variable SECRET_ANTI_CSRF con algun valor aleatorio');
        }

        self::$script     = $_SERVER['SCRIPT_NAME'];
        self::$formy_csrf = $_POST['formy_csrf'] ?? '';
        self::$dirname    = dirname( self::$script );
        self::$usuario    = $_SESSION['UsuarioConectado'] ?? 'sinusuario';
        self::$secret     = $_ENV['SECRET_ANTI_CSRF'];
    }


    // Return TOKEN from time()
    static function getTokenCSRF( $time ) {
        return hash_hmac( 'sha512', self::$dirname . $time, self::$usuario . self::$secret);
    }


    // Creo un TOKEN y guardo la HORA en un array de SESSION para este SCRIPT
    static function hashCSRF( $formy = true ) {
      $time  = microtime( true );
      $token = self::getTokenCSRF( $time );

      if( $formy ) {
        self::addTime( $time );
      }
      
      return $token;
    }



    // control de CSRF valido
    static function validacionCSRF() {

      // si es un POST sobre un archivo que arranca con el nombre UPD....
      if( preg_match('/^upd/i', basename(self::$script) ) ) {

        // que no exista el array en session para esta ruta, es un error casi imposible que suceda
        if( isset( self::$formy_csrf ) && isset( $_SESSION['dpsCSRF'] ) ) {

          //recorro el array de horarios CSRF para este script y verifico si es el correcto            
          foreach( self::getAllTokens() as $idx => $time ) {

            if( hash_equals( self::getTokenCSRF( $time ), self::$formy_csrf ) ) {
              // borro el token usado
              self::delTimeByIndex( $idx );

              // Genero un nuevo token y lo dejo 'asociado' al viejo para poder encontrarlo luego desde el UPD.TPL
              $_SESSION['newCSRFToken'][self::$formy_csrf] = self::hashCSRF();

              return true; // encontre un HASH válido. SALGO DEL CONTROL
            }
          }
        }      

        // si estoy aca es porque recorri todos los horarios de CSRF para este script y ninguno coincide
        // o bien no existe en session el array de tokens ( algo raro )
        return false;

      } else {
        return true; // NO es un Post o NO ES un updxxxxx.php
      }
    }



    private static function getAllTokens( ) {       
        return $_SESSION['dpsCSRF'] ?? [];
    }

    private static function delTimeByIndex( $indice ) {       
        unset( $_SESSION['dpsCSRF'][ $indice ] );
    }

    static private function addTime( $time ) {
        $_SESSION['dpsCSRF'][] = $time;
    }

}