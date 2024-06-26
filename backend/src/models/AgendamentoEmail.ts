// models/AgendamentoEmail.ts
import {
  BelongsTo,
  Column,
  DataType,
  ForeignKey,
  Model,
  Table
} from "sequelize-typescript";
import Company from "./Company";

@Table
class AgendamentoEmail extends Model<AgendamentoEmail> {
  @Column
  email: string;

  @Column
  subject: string;

  @Column(DataType.TEXT)
  message: string;

  @Column
  dataAgendamento: Date; // Armazena a data e hora do agendamento

  @ForeignKey(() => Company)
  @Column
  companyId: number;

  @BelongsTo(() => Company)
  company: Company;
}

export default AgendamentoEmail;
