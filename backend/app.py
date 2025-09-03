import sys
import libvirt
import os
from flask import Flask, jsonify, request
from xml.etree import ElementTree

app = Flask(__name__)

# --- Configuration ---
# Assumes the script is run from the project root
BASE_IMAGE_DIR = os.path.abspath("base_images")

# --- Libvirt Connection ---
def get_libvirt_connection():
    """Establishes a connection to the libvirt daemon."""
    try:
        conn = libvirt.open('qemu:///system')
        if conn is None:
            app.logger.error('Failed to open connection to qemu:///system')
            return None
        return conn
    except libvirt.libvirtError as e:
        app.logger.error(f'Failed to connect to libvirt: {e}')
        return None

# --- Scenario Definitions ---
SCENARIOS = {
    'small_corporate_network': {
        'id': 'small_corporate_network',
        'name': 'Small Corporate Network Compromise',
        'description': 'A simple network with a firewall/router and a vulnerable web server.',
        'status': 'stopped',
        'vms': [
            {
                'name': 'scenario1-web',
                'base_image': 'vulnerable-linux.qcow2',
                'ram_mb': 2048,
                'vcpus': 1,
            },
            {
                'name': 'scenario1-router',
                'base_image': 'vyos-rolling-latest.qcow2',
                'ram_mb': 1024,
                'vcpus': 1,
            }
        ],
        'network': {
            'name': 'scenario1-net',
            'subnet': '192.168.100.0',
            'mask': '255.255.255.0'
        }
    }
}

# --- Libvirt XML Helper Functions ---
def generate_network_xml(network_info):
    """Generates libvirt network XML for a NAT network."""
    return f"""
    <network>
      <name>{network_info['name']}</name>
      <bridge name='{network_info['name']}_br' stp='on' delay='0'/>
      <mac address='52:54:00:8a:b3:c1'/>
      <ip address='{network_info['subnet'][:-1]}1' netmask='{network_info['mask']}'>
        <dhcp>
          <range start='{network_info['subnet'][:-1]}100' end='{network_info['subnet'][:-1]}200'/>
        </dhcp>
      </ip>
    </network>
    """

def generate_vm_xml(vm_info, network_name):
    """Generates libvirt domain (VM) XML."""
    disk_path = os.path.join(BASE_IMAGE_DIR, vm_info['base_image'])
    return f"""
    <domain type='kvm'>
      <name>{vm_info['name']}</name>
      <memory unit='MiB'>{vm_info['ram_mb']}</memory>
      <vcpu placement='static'>{vm_info['vcpus']}</vcpu>
      <os>
        <type arch='x86_64' machine='pc-q35-8.2'>hvm</type>
        <boot dev='hd'/>
      </os>
      <devices>
        <disk type='file' device='disk'>
          <driver name='qemu' type='qcow2'/>
          <source file='{disk_path}'/>
          <target dev='vda' bus='virtio'/>
        </disk>
        <interface type='network'>
          <source network='{network_name}'/>
          <model type='virtio'/>
        </interface>
        <serial type='pty'>
          <target type='isa-serial' port='0'>
            <model name='isa-serial'/>
          </target>
        </serial>
        <console type='pty'>
          <target type='serial' port='0'/>
        </console>
        <graphics type='vnc' port='-1' autoport='yes' listen='127.0.0.1'>
          <listen type='address' address='127.0.0.1'/>
        </graphics>
      </devices>
    </domain>
    """

# --- API Endpoints ---
@app.route('/api/status')
def status():
    # ... (same as before, omitted for brevity)
    return jsonify({'status': 'ok'})


@app.route('/api/scenarios', methods=['GET'])
def get_scenarios():
    """Lists all available scenarios."""
    return jsonify(list(SCENARIOS.values()))

@app.route('/api/scenarios/<scenario_id>/start', methods=['POST'])
def start_scenario(scenario_id):
    """Starts a given scenario."""
    if scenario_id not in SCENARIOS:
        return jsonify({'error': 'Scenario not found'}), 404

    scenario = SCENARIOS[scenario_id]
    conn = get_libvirt_connection()
    if not conn:
        return jsonify({'error': 'Failed to connect to libvirt'}), 500

    try:
        # 1. Create Network
        app.logger.info(f"Creating network: {scenario['network']['name']}")
        network_xml = generate_network_xml(scenario['network'])
        net = conn.networkDefineXML(network_xml)
        net.create()
        app.logger.info("Network created successfully.")

        # 2. Create VMs
        for vm_info in scenario['vms']:
            app.logger.info(f"Creating VM: {vm_info['name']}")
            vm_xml = generate_vm_xml(vm_info, scenario['network']['name'])
            dom = conn.defineXML(vm_xml)
            dom.create()
            app.logger.info(f"VM {vm_info['name']} started successfully.")

        scenario['status'] = 'running'
        return jsonify({'message': f'Scenario "{scenario_id}" started successfully.'})

    except libvirt.libvirtError as e:
        app.logger.error(f"Libvirt error starting scenario {scenario_id}: {e}")
        # Attempt to clean up on failure
        stop_scenario(scenario_id)
        return jsonify({'error': f'Failed to start scenario: {e}'}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/scenarios/<scenario_id>/stop', methods=['POST'])
def stop_scenario(scenario_id):
    """Stops a given scenario."""
    if scenario_id not in SCENARIOS:
        return jsonify({'error': 'Scenario not found'}), 404

    scenario = SCENARIOS[scenario_id]
    conn = get_libvirt_connection()
    if not conn:
        return jsonify({'error': 'Failed to connect to libvirt'}), 500

    try:
        # 1. Stop VMs
        for vm_info in scenario['vms']:
            try:
                dom = conn.lookupByName(vm_info['name'])
                if dom.isActive():
                    app.logger.info(f"Destroying VM: {vm_info['name']}")
                    dom.destroy()
                app.logger.info(f"Undefining VM: {vm_info['name']}")
                dom.undefine()
            except libvirt.libvirtError as e:
                app.logger.warning(f"Could not stop VM {vm_info['name']} (may already be stopped): {e}")

        # 2. Stop Network
        try:
            net = conn.networkLookupByName(scenario['network']['name'])
            if net.isActive():
                app.logger.info(f"Destroying network: {scenario['network']['name']}")
                net.destroy()
            app.logger.info(f"Undefining network: {scenario['network']['name']}")
            net.undefine()
        except libvirt.libvirtError as e:
            app.logger.warning(f"Could not stop network {scenario['network']['name']} (may already be stopped): {e}")

        scenario['status'] = 'stopped'
        return jsonify({'message': f'Scenario "{scenario_id}" stopped successfully.'})

    except Exception as e:
        app.logger.error(f"Generic error stopping scenario {scenario_id}: {e}")
        return jsonify({'error': f'Failed to stop scenario: {e}'}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/scenarios/<scenario_id>/status', methods=['GET'])
def scenario_status(scenario_id):
    """Gets the status of a specific scenario."""
    if scenario_id not in SCENARIOS:
        return jsonify({'error': 'Scenario not found'}), 404

    scenario = SCENARIOS[scenario_id]
    conn = get_libvirt_connection()
    if not conn:
        return jsonify({'error': 'Failed to connect to libvirt'}), 500

    status_data = {
        'name': scenario['name'],
        'status': scenario['status'],
        'vms': []
    }

    if scenario['status'] == 'running':
        try:
            net = conn.networkLookupByName(scenario['network']['name'])
            for vm_info in scenario['vms']:
                vm_data = {'name': vm_info['name'], 'state': 'unknown', 'ip': 'N/A'}
                try:
                    dom = conn.lookupByName(vm_info['name'])
                    state, _ = dom.state()
                    vm_data['state'] = state

                    # Get IP from DHCP leases
                    macs = ElementTree.fromstring(dom.XMLDesc(0)).findall('.//interface/mac')
                    if macs:
                        mac = macs[0].get('address')
                        leases = net.DHCPLeases()
                        for lease in leases:
                            if lease['mac'] == mac:
                                vm_data['ip'] = lease['ipaddr']
                                break
                except libvirt.libvirtError:
                     vm_data['state'] = 'not found'
                status_data['vms'].append(vm_data)
        except libvirt.libvirtError:
            status_data['network_status'] = 'not found'
        finally:
            if conn:
                conn.close()

    return jsonify(status_data)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
