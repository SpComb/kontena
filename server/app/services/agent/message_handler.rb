module Agent
  class MessageHandler
    include EventStream::GridEventNotifier

    ##
    # @param [Queue] queue
    def initialize(queue)
      @queue = queue
    end

    def run
      Thread.new {
        loop do
          begin
            message = @queue.pop
            self.handle_message(message)
          rescue => exc
            puts "#{exc.class.name}: #{exc.message}"
            puts exc.backtrace.join("\n") if exc.backtrace
          end
        end
      }
    end

    ##
    # @param [Hash] message
    def handle_message(message)
      grid = Grid.find_by(id: message['grid_id'])
      return if grid.nil?

      data = message['data']
      case data['event']
        when 'node:info'.freeze
          self.on_node_info(grid, data['data'])
        when 'container:info'.freeze
          self.on_container_info(grid, data['data'])
        when 'container:event'.freeze
          self.on_container_event(grid, data['data'])
        when 'container:log'.freeze
          self.on_container_log(grid, message['node_id'], data['data'])
        when 'container:stats'.freeze
          self.on_container_stat(grid, data['data'])
        else
          puts "unknown event: #{message}"
      end
    end

    ##
    # @param [Grid] grid
    # @param [Hash] data
    def on_node_info(grid, data)
      node = with_cache{ grid.host_nodes.find_by(node_id: data['ID']) }
      if !node
        node = grid.host_nodes.build
      end
      node.attributes_from_docker(data)
      node.save!
      trigger_grid_event(node.grid, 'node', 'update', HostNodeSerializer.new(node).to_hash)
      node
    end

    ##
    # @param [Grid] grid
    # @param [Hash] data
    def on_container_info(grid, data)
      info_mapper = ContainerInfoMapper.new(grid)
      info_mapper.from_agent(data)
    end

    ##
    # @param [Grid] grid
    # @param [Hash] data
    def on_container_event(grid, data)
      container = with_cache{ grid.containers.unscoped.find_by(container_id: data['id']) }
      if container
        if data['status'] == 'destroy'
          container.mark_for_delete
          trigger_grid_event(grid, 'container', 'delete', ContainerSerializer.new(container).to_hash)
        elsif data['status'] == 'deployed'
          container.set(:container_id => data['id'], :deploy_rev => data['deploy_rev'])
        end
      end
    end

    ##
    # @param [Grid] grid
    # @param [String] node_id
    # @param [Hash] data
    def on_container_log(grid, node_id, data)
      container = with_cache{ grid.containers.find_by(container_id: data['id']) }
      if container
        if data['time']
          created_at = Time.parse(data['time'])
        else
          created_at = Time.now.utc
        end
        ContainerLog.with(safe: false).create(
            grid: grid,
            host_node_id: node_id,
            grid_service: container.grid_service,
            container: container,
            created_at: created_at,
            name: container.name,
            type: data['type'],
            data: data['data']
        )
      end
    end

    ##
    # @param [Grid] grid
    # @param [Hash] data
    def on_container_stat(grid, data)
      container = with_cache{ grid.containers.find_by(container_id: data['id']) }
      if container
        data = fixnums_to_float(data)
        ContainerStat.with(safe: false).create(
            grid: grid,
            grid_service: container.grid_service,
            container: container,
            spec: data['spec'],
            cpu: data['cpu'],
            memory: data['memory'],
            filesystem: data['filesystem'],
            diskio: data['diskio'],
            network: data['network']
        )
      end
    end

    ##
    # @param [Hash,Array]
    # @return [Hash,Array]
    def fixnums_to_float(h)
      i = 0
      h.each do |k, v|
        # If v is nil, an array is being iterated and the value is k.
        # If v is not nil, a hash is being iterated and the value is v.
        #
        value = v || k

        if value.is_a?(Hash) || value.is_a?(Array)
          fixnums_to_float(value)
        else
          if !v.nil? && value.is_a?(Bignum)
            h[k] = value.to_f
          elsif v.nil? && value.is_a?(Bignum)
            h[i] = value.to_f
          end
        end
        i += 1
      end
    end

    def with_cache
      Mongoid::QueryCache.cache { yield }
    end
  end
end
