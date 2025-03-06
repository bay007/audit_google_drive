import os
import csv
import time
import logging
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='drive_audit.log'
)

# Definir los alcances (scopes) requeridos
SCOPES = ['https://www.googleapis.com/auth/drive.metadata.readonly']
TOKEN_FILE = 'token.json'
CREDENTIALS_FILE = 'credentials.json'
OUTPUT_FILE = 'drive_permissions_report.csv'

def authenticate():
    """Autentica al usuario y devuelve el servicio de la API de Google Drive."""
    creds = None
    
    # El archivo token.json almacena los tokens de acceso y actualización del usuario
    if os.path.exists(TOKEN_FILE):
        try:
            creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
        except Exception as e:
            logging.error(f"Error al leer el archivo de token: {e}")
            return None
    
    # Si no hay credenciales válidas, inicia sesión
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception as e:
                logging.error(f"Error al actualizar el token: {e}")
                # Si falla la actualización, mejor iniciar nuevo flujo de autenticación
                creds = None
                
        if not creds:
            try:
                if not os.path.exists(CREDENTIALS_FILE):
                    logging.error(f"No se encontró el archivo {CREDENTIALS_FILE}")
                    return None
                    
                flow = InstalledAppFlow.from_client_secrets_file(
                    CREDENTIALS_FILE, SCOPES)
                creds = flow.run_local_server(port=0)
                
                # Guarda las credenciales para la próxima ejecución
                with open(TOKEN_FILE, 'w') as token:
                    token.write(creds.to_json())
                    
            except Exception as e:
                logging.error(f"Error en el proceso de autenticación: {e}")
                return None
    
    try:
        service = build('drive', 'v3', credentials=creds)
        return service
    except HttpError as error:
        logging.error(f'Error al crear el servicio de Drive: {error}')
        return None

def get_permissions(service, file_id):
    """Obtiene los permisos de un archivo o carpeta."""
    if not service or not file_id:
        return []
        
    try:
        permissions = service.permissions().list(
            fileId=file_id, 
            fields='permissions(id,emailAddress,role,type)'
        ).execute()
        return permissions.get('permissions', [])
    except HttpError as error:
        if error.resp.status == 404:
            logging.warning(f'Archivo/carpeta no encontrado (ID: {file_id})')
        else:
            logging.error(f'Error al obtener permisos para {file_id}: {error}')
        return []

def list_files(service, query, page_token=None, collected_items=None):
    """Lista archivos y carpetas en Google Drive según una consulta con manejo de paginación."""
    if collected_items is None:
        collected_items = []
    
    if not service:
        return collected_items
        
    try:
        results = service.files().list(
            q=query,
            fields="nextPageToken, files(id, name, mimeType, parents)",
            pageSize=1000,
            pageToken=page_token
        ).execute()
        
        items = results.get('files', [])
        collected_items.extend(items)
        
        # Manejar paginación si hay más resultados
        next_page_token = results.get('nextPageToken')
        if next_page_token:
            return list_files(service, query, next_page_token, collected_items)
            
        return collected_items
    except HttpError as error:
        logging.error(f'Error al listar archivos: {error}')
        return collected_items

def traverse_drive(service, parent_id, parent_path, csv_writer, items_processed=0, max_items=None):
    """Recorre recursivamente todas las carpetas y archivos en Google Drive."""
    if max_items and items_processed >= max_items:
        logging.info(f"Se alcanzó el límite máximo de elementos ({max_items})")
        return items_processed
        
    if not service or not parent_id:
        return items_processed
        
    query = f"'{parent_id}' in parents and trashed = false"
    items = list_files(service, query)
    
    for item in items:
        try:
            item_name = item.get('name', 'Sin nombre')
            item_path = os.path.join(parent_path, item_name)
            item_id = item.get('id')
            item_type = item.get('mimeType', 'unknown')
            
            logging.info(f"Procesando: {item_path}")
            
            permissions = get_permissions(service, item_id)
            
            # Si no hay permisos, registrar al menos la entrada del archivo
            if not permissions:
                csv_writer.writerow([item_path, item_type, 'N/A', 'N/A', 'N/A'])
                items_processed += 1
            else:
                for perm in permissions:
                    csv_writer.writerow([
                        item_path, 
                        item_type, 
                        perm.get('emailAddress', 'N/A'), 
                        perm.get('role', 'N/A'),
                        perm.get('type', 'N/A')
                    ])
                    items_processed += 1
            
            # Verificar límite después de procesar cada archivo
            if max_items and items_processed >= max_items:
                return items_processed
                
            # Recorrer carpetas recursivamente
            if item_type == 'application/vnd.google-apps.folder':
                items_processed = traverse_drive(service, item_id, item_path, csv_writer, 
                                               items_processed, max_items)
                
        except Exception as e:
            logging.error(f"Error al procesar el elemento {item.get('id', 'desconocido')}: {e}")
            
    return items_processed

def main(max_items=None):
    """Función principal para ejecutar la auditoría."""
    try:
        logging.info("Iniciando auditoría de permisos de Google Drive")
        
        service = authenticate()
        if not service:
            logging.error("No se pudo autenticar con Google Drive")
            return False
            
        # Crear directorio para el archivo de salida si no existe
        output_dir = os.path.dirname(OUTPUT_FILE)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        with open(OUTPUT_FILE, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(['Path', 'Type', 'User', 'Role', 'Permission Type'])
            
            # Comienza desde la carpeta raíz del usuario
            items_processed = traverse_drive(service, 'root', '', writer, 0, max_items)
            
        logging.info(f'El informe de permisos se ha generado como {OUTPUT_FILE}')
        logging.info(f'Total de elementos procesados: {items_processed}')
        return True
        
    except Exception as e:
        logging.critical(f"Error crítico en la ejecución principal: {e}")
        return False

if __name__ == '__main__':
    start_time = time.time()
    
    # Limitar el número de elementos a procesar (opcional)
    # max_items = 10000  # Descomentar para establecer un límite
    max_items = None
    
    success = main(max_items)
    
    elapsed_time = time.time() - start_time
    logging.info(f'Tiempo total de ejecución: {elapsed_time:.2f} segundos')
    print(f'Tiempo total de ejecución: {elapsed_time:.2f} segundos')
    
    if success:
        print(f'El informe de permisos se ha generado correctamente como {OUTPUT_FILE}')
    else:
        print('Ocurrieron errores durante la ejecución. Consulte el archivo drive_audit.log para más detalles.')
