from pyflink.datastream import StreamExecutionEnvironment
env = StreamExecutionEnvironment.get_execution_environment()
env.set_parallelism(1)
ds = env.from_collection(["a", "bb", "ccc"]).map(lambda s: s.upper() + str(len(s)))
print(list(ds.execute_and_collect()))
