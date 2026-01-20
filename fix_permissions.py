import sys
sys.path.append('/app')
from mwdb.cli.base import create_app
from mwdb.model import db, User, Group
from mwdb.core.capabilities import Capabilities

def fix_permissions():
    print("Fixing permissions for admin user...")
    app = create_app()
    with app.app_context():
        group = Group.query.filter(Group.name == 'admin').first()
        
        if not group:
            print("Admin group not found!")
            u = User.query.filter(User.login == 'admin').first()
            if u:
                for g in u.groups:
                    if g.name == 'admin':
                        group = g
                        break
        
        if not group:
            print("Could not locate admin capability group.")
            return

        print(f"Updating capabilities for group '{group.name}'...")
        current_caps = set(group.capabilities or [])
        
        # Correct attribute names based on cat output
        new_caps = {
            Capabilities.adding_files,
            Capabilities.access_all_objects,
            Capabilities.manage_users,
            Capabilities.manage_profile,
            Capabilities.share_queried_objects,
            Capabilities.sharing_with_all,
            Capabilities.access_uploader_info,
            Capabilities.adding_tags,
            Capabilities.removing_tags,
            Capabilities.adding_comments,
            Capabilities.removing_comments,
            Capabilities.adding_parents,
            Capabilities.removing_parents,
            Capabilities.reading_all_attributes,
            Capabilities.adding_all_attributes,
            Capabilities.removing_attributes,
            Capabilities.adding_configs,
            Capabilities.adding_blobs,
            Capabilities.unlimited_requests,
            Capabilities.removing_objects,
            Capabilities.karton_assign,
            Capabilities.karton_reanalyze,
            Capabilities.karton_unassign,
            Capabilities.modify_3rd_party_sharing,
            Capabilities.access_prometheus_metrics
        }
        
        updated_caps = list(current_caps.union(new_caps))
        group.capabilities = updated_caps
        
        db.session.add(group)
        db.session.commit()
        print(f"Capabilities updated successfully.")

def register_metakeys():
    print("Registering metakeys for analysis attributes...")
    from mwdb.cli.base import create_app
    from mwdb.model import db
    from mwdb.model.attribute import AttributeDefinition
    
    app = create_app()
    with app.app_context():
        # List of required metakeys
        metakeys = [
            ("sig_path", "Original file path"),
            ("sig_verified", "Digital signature status"),
            ("sig_date", "Signature date"),
            ("sig_publisher", "Digital signature publisher"),
            ("sig_company", "Company name"),
            ("sig_description", "File description"),
            ("sig_product", "Product name"),
            ("sig_product_version", "Product version"),
            ("sig_file_version", "Binary file version"),
            ("sig_machine_type", "Machine type (e.g. 64-bit)"),
            ("sig_md5", "File MD5 hash"),
            ("sig_sha1", "File SHA1 hash"),
            ("sig_pesha1", "PE SHA1 hash"),
            ("sig_pesha256", "PE SHA256 hash"),
            ("sig_sha256", "File SHA256 hash"),
            ("sig_imp", "Import hash"),
            ("sig_entropy", "Shannon entropy"),
            ("ioctl_vuln_count", "IOCTLance vulnerability count"),
            ("ioctl_verdict", "IOCTLance analysis verdict"),
        ]
        
        for key, description in metakeys:
            # Check if exists
            existing = AttributeDefinition.query.filter(AttributeDefinition.key == key).first()
            if not existing:
                print(f"Defining metakey: {key}")
                attr_def = AttributeDefinition(
                    key=key, 
                    label=key, 
                    description=description, 
                    hidden=False,
                    url_template="",
                    rich_template="",
                    example_value=""
                )
                db.session.add(attr_def)
        
        db.session.commit()
        print("Metakeys registered.")

if __name__ == "__main__":
    fix_permissions()
    register_metakeys()
