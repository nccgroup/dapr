import { connect } from "react-redux";
import StructDissection from "../components/struct-dissection";
import { State } from "../reducers/table-view";
import { dissectorSelectType } from "../actions/actions";
import { selectCurrentGrouping, selectTypeByName } from "../utils/selectors";
import * as _ from "lodash";
import { Struct } from "../types/struct-def";
import { TypeDissectorProps } from "../types/type-dissector-props";
import { Buffer } from "buffer/";

const mapStateToProps = (state: State): TypeDissectorProps => {
  const props: TypeDissectorProps = {
    selectedTypeForDissector: selectTypeByName(
      state.selectedTypeForDissector,
      state.types
    ),
    types: state.types,
    data:
      state.selectedEventID === -1
        ? []
        : _.filter(
            selectCurrentGrouping(
              state.events,
              state.selectedDriver,
              state.selectedDupEventKey
            ),
            i => i.id === state.selectedEventID
          )[0].data,
    fields: [],
    dissectorSelectType: (t: string) => {
      return;
    }
  };
  if (
    !!props.selectedTypeForDissector &&
    !!props.data &&
    props.data.length > 0
  ) {
    const struct: Struct = new Struct(
      props.selectedTypeForDissector,
      Buffer.from(props.data)
    );
    props.fields = struct.fields;
  }
  return props;
};

// Here, we make a function available to the components/struct-dissector
// which handles the case when a struct to apply is picked. When we use
// mapDispatchtoprops in this way, the component will have a function
// called `this.props.dissectorSelectType`.
const mapDispatchToProps = (dispatch: any) => ({
  dissectorSelectType: (struct: string) => dispatch(dissectorSelectType(struct))
});

export default connect(mapStateToProps, mapDispatchToProps)(StructDissection);
